package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"aps.local/apps/api/internal/ldap"
)

// --- LDAP diagnostics (admin page: connection settings + test auth) -------

type ldapConfigInput struct {
	Authorization string `header:"Authorization" required:"true"`
}

type ldapConfigOutput struct {
	Body ldap.SettingsView
}

type ldapTestInput struct {
	Authorization string `header:"Authorization" required:"true"`
	Body          struct {
		Username string `json:"username" minLength:"1" maxLength:"128" doc:"логин: короткое имя, DOMAIN\\user или user@UPN"`
		Password string `json:"password" minLength:"1" maxLength:"256" format:"password"`
	}
}

type ldapTestOutput struct {
	Body struct {
		Trace ldap.Trace       `json:"trace"`
		User  *ldap.PublicUser `json:"user,omitempty"`
	}
}

func registerLDAP(api huma.API, d Deps) {
	huma.Register(api, huma.Operation{
		OperationID: "getLdapConfig",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/ldap/config",
		Summary:     "Текущие настройки подключения к LDAP (admin)",
		Description: "Секреты (пароль сервисной учётки) никогда не возвращаются.",
		Security:    bearerSecurity,
		Tags:        []string{"ldap"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden},
	}, func(ctx context.Context, in *ldapConfigInput) (*ldapConfigOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		return &ldapConfigOutput{Body: d.LDAP.Config().View()}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "testLdapAuth",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/ldap/test",
		Summary:     "Проверка авторизации в LDAP с пошаговым отчётом (admin)",
		Description: "Выполняет ту же цепочку, что и вход (TLS → bind → search → атрибуты → роли). Ответ всегда 200 с отчётом: OK или подробный лог отказа. Пароль используется только для bind и не сохраняется.",
		Security:    bearerSecurity,
		Tags:        []string{"ldap"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest},
	}, func(ctx context.Context, in *ldapTestInput) (*ldapTestOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		trace, user := d.LDAP.TestAuth(in.Body.Username, in.Body.Password)
		out := &ldapTestOutput{}
		out.Body.Trace = *trace
		if user != nil {
			out.Body.User = user.Public()
		}
		return out, nil
	})
}
