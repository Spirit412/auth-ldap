package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/session"
	"aps.local/apps/api/internal/userstore"
)

// --- sessions (F-05, F-06) ---------------------------------------------------

type sessionsInput struct {
	Authorization string `header:"Authorization" required:"true"`
	Username      string `query:"username" maxLength:"128" doc:"filter by exact username"`
	Limit         int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor        string `query:"cursor" maxLength:"128" doc:"opaque pagination cursor"`
}

type sessionItem struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
}

type sessionsOutput struct {
	Body struct {
		Items      []sessionItem `json:"items"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}
}

type revokeSessionInput struct {
	Authorization string `header:"Authorization" required:"true"`
	ID            string `path:"id" minLength:"1" maxLength:"64" doc:"session family id"`
}

type revokeSessionOutput struct {
	Status int `json:"-"`
}

func registerAdmin(api huma.API, d Deps) {
	huma.Register(api, huma.Operation{
		OperationID: "listSessions",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/sessions",
		Summary:     "List active sessions (admin)",
		Description: "Refresh-session families with filter ?username= and cursor pagination.",
		Security:    bearerSecurity,
		Tags:        []string{"sessions"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *sessionsInput) (*sessionsOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		items, next, err := d.Svc.Sessions(ctx, in.Username, in.Limit, in.Cursor)
		if err != nil {
			return nil, fail(ctx, err)
		}
		out := &sessionsOutput{}
		out.Body.NextCursor = next
		out.Body.Items = make([]sessionItem, 0, len(items))
		for _, it := range items {
			out.Body.Items = append(out.Body.Items, sessionItem{
				ID:        it.ID,
				Username:  it.Username,
				CreatedAt: it.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				UserAgent: it.UserAgent,
				IP:        it.IP,
			})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "revokeSession",
		Method:        http.MethodDelete,
		Path:          "/api/v1/auth/sessions/{id}",
		Summary:       "Revoke a session family (admin)",
		DefaultStatus: http.StatusNoContent,
		Security:      bearerSecurity,
		Tags:          []string{"sessions"},
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *revokeSessionInput) (*revokeSessionOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		err = d.Svc.RevokeSession(ctx, claims.Subject, in.ID)
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil, fail(ctx, auth.ErrNotFound("session not found"))
		}
		if err != nil {
			return nil, fail(ctx, auth.ErrUnavailable())
		}
		return &revokeSessionOutput{Status: http.StatusNoContent}, nil
	})

	// --- users (PostgreSQL profile cache) ------------------------------------

	type usersInput struct {
		Authorization string `header:"Authorization" required:"true"`
		Q             string `query:"q" maxLength:"128" doc:"substring filter over username / display_name / email"`
		Status        string `query:"status" enum:"active,deleted,all" default:"active"`
		Role          string `query:"role" maxLength:"64" doc:"exact role filter, e.g. admin"`
		Limit         int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Cursor        string `query:"cursor" maxLength:"255" doc:"keyset cursor: last username of previous page"`
	}
	type usersOutput struct {
		Body struct {
			Items      []userstore.User `json:"items"`
			NextCursor string           `json:"next_cursor,omitempty"`
		}
	}
	type userByIDInput struct {
		Authorization string `header:"Authorization" required:"true"`
		ID            string `path:"id" format:"uuid"`
	}
	type userOutput struct {
		Body userstore.User
	}
	type deleteUserInput struct {
		Authorization string `header:"Authorization" required:"true"`
		ID            string `path:"id" format:"uuid"`
	}
	type deleteUserOutput struct {
		Status int `json:"-"`
	}

	huma.Register(api, huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        "/api/v1/users",
		Summary:     "List cached user profiles (admin)",
		Description: "Local PostgreSQL profile cache populated at each login (no passwords). Filter by substring, status and role; keyset pagination by username.",
		Security:    bearerSecurity,
		Tags:        []string{"users"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *usersInput) (*usersOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		items, next, err := d.Svc.Users(ctx, userstore.ListFilter{
			Query:  in.Q,
			Status: in.Status,
			Role:   in.Role,
			Limit:  in.Limit,
			Cursor: in.Cursor,
		})
		if err != nil {
			return nil, fail(ctx, err)
		}
		out := &usersOutput{}
		out.Body.Items = items
		out.Body.NextCursor = next
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/{id}",
		Summary:     "Get a cached user profile (admin)",
		Security:    bearerSecurity,
		Tags:        []string{"users"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *userByIDInput) (*userOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, fail(ctx, auth.ErrBadRequest("invalid user id"))
		}
		u, err := d.Svc.UserByIDAny(ctx, id)
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &userOutput{Body: *u}, nil
	})

	type updateUserInput struct {
		Authorization string `header:"Authorization" required:"true"`
		ID            string `path:"id" format:"uuid"`
		Body          struct {
			DisplayName string `json:"display_name" maxLength:"512" doc:"новое отображаемое имя (локальная правка; AD перезапишет при следующем входе)"`
			Email       string `json:"email" maxLength:"512" format:"email" doc:"новый email (локальная правка; AD перезапишет при следующем входе)"`
		}
	}
	type updateUserOutput struct {
		Body userstore.User
	}
	type restoreUserInput struct {
		Authorization string `header:"Authorization" required:"true"`
		ID            string `path:"id" format:"uuid"`
	}
	type restoreUserOutput struct {
		Body userstore.User
	}

	huma.Register(api, huma.Operation{
		OperationID: "updateUser",
		Method:      http.MethodPatch,
		Path:        "/api/v1/users/{id}",
		Summary:     "Локальная правка display_name / email профиля (admin)",
		Description: "Правится кэш в PostgreSQL; при следующем входе пользователя поля будут перезаписаны значениями из AD.",
		Security:    bearerSecurity,
		Tags:        []string{"users"},
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *updateUserInput) (*updateUserOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, fail(ctx, auth.ErrBadRequest("invalid user id"))
		}
		u, err := d.Svc.UpdateUserProfile(ctx, claims.Subject, id, in.Body.DisplayName, in.Body.Email)
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &updateUserOutput{Body: *u}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "restoreUser",
		Method:      http.MethodPost,
		Path:        "/api/v1/users/{id}/restore",
		Summary:     "Восстановить soft-deleted профиль (admin)",
		Security:    bearerSecurity,
		Tags:        []string{"users"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *restoreUserInput) (*restoreUserOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, fail(ctx, auth.ErrBadRequest("invalid user id"))
		}
		u, err := d.Svc.RestoreUser(ctx, claims.Subject, id)
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &restoreUserOutput{Body: *u}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "deleteUser",
		Method:        http.MethodDelete,
		Path:          "/api/v1/users/{id}",
		Summary:       "Soft-delete a profile and revoke its sessions (admin)",
		Description:   "Sets deleted_at and revokes all refresh sessions of the user. AD remains the source of truth: the next login re-activates the profile.",
		DefaultStatus: http.StatusNoContent,
		Security:      bearerSecurity,
		Tags:          []string{"users"},
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, fail(ctx, auth.ErrBadRequest("invalid user id"))
		}
		if err := d.Svc.DeleteUser(ctx, claims.Subject, id); err != nil {
			return nil, fail(ctx, err)
		}
		return &deleteUserOutput{Status: http.StatusNoContent}, nil
	})
}
