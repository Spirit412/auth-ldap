package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/danielgtaylor/huma/v2"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/logstore"
)

// --- admin log viewer (файловые логи состояния, retention 3 дня) ------------

type logDatesInput struct {
	Authorization string `header:"Authorization" required:"true"`
}

type logDatesOutput struct {
	Body struct {
		Dates []string `json:"dates"`
	}
}

type logsInput struct {
	Authorization string `header:"Authorization" required:"true"`
	Date          string `query:"date" minLength:"10" maxLength:"10" doc:"дата в формате YYYY-MM-DD; по умолчанию — самый поздний доступный файл"`
	Offset        int    `query:"offset" default:"0" minimum:"0"`
	Limit         int    `query:"limit" default:"200" minimum:"1" maximum:"1000"`
	Level         string `query:"level" enum:"debug,info,warn,error" doc:"фильтр по уровню (после чтения)"`
	Event         string `query:"event" maxLength:"64" doc:"фильтр по полю event (после чтения)"`
}

type logsOutput struct {
	Body struct {
		Items      []logstore.Entry `json:"items"`
		NextOffset int              `json:"next_offset"`
	}
}

func registerLogs(api huma.API, d Deps) {
	huma.Register(api, huma.Operation{
		OperationID: "listLogDates",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/logs/dates",
		Summary:     "Доступные даты файлов логов (admin)",
		Security:    bearerSecurity,
		Tags:        []string{"logs"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *logDatesInput) (*logDatesOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		if d.LogDir == "" {
			return nil, fail(ctx, auth.ErrBadRequest("file logging is disabled (LOG_FILE_DIR is empty)"))
		}
		dates, err := logstore.Dates(d.LogDir)
		if err != nil {
			return nil, fail(ctx, auth.ErrUnavailable())
		}
		out := &logDatesOutput{}
		out.Body.Dates = dates
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "readLogs",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/logs",
		Summary:     "Построчное чтение файла лога за дату (admin)",
		Description: "JSON-строки файла aps-YYYYMMDD.log. Файлы старше LOG_RETENTION_DAYS дней удаляются автоматически.",
		Security:    bearerSecurity,
		Tags:        []string{"logs"},
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *logsInput) (*logsOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := requireAdmin(claims); err != nil {
			return nil, fail(ctx, err)
		}
		if d.LogDir == "" {
			return nil, fail(ctx, auth.ErrBadRequest("file logging is disabled (LOG_FILE_DIR is empty)"))
		}
		date := in.Date
		if date == "" {
			dates, err := logstore.Dates(d.LogDir)
			if err != nil {
				return nil, fail(ctx, auth.ErrUnavailable())
			}
			if len(dates) == 0 {
				return nil, fail(ctx, auth.ErrNotFound("no log files yet"))
			}
			date = dates[0]
		}
		items, next, err := logstore.Read(d.LogDir, date, in.Offset, in.Limit)
		switch {
		case errors.Is(err, logstore.ErrBadDate):
			return nil, fail(ctx, auth.ErrBadRequest("date must be YYYY-MM-DD"))
		case errors.Is(err, logstore.ErrNoFile):
			return nil, fail(ctx, auth.ErrNotFound("no log file for this date"))
		case err != nil:
			return nil, fail(ctx, auth.ErrUnavailable())
		}
		// Фильтры применяются после чтения; при active-фильтре offset-семантика
		// становится "страничной по сырым строкам", что для просмотра логов
		// достаточно.
		if in.Level != "" || in.Event != "" {
			filtered := make([]logstore.Entry, 0, len(items))
			for _, e := range items {
				if in.Level != "" && !entryMatches(e, "level", in.Level) {
					continue
				}
				if in.Event != "" && !entryMatches(e, "event", in.Event) {
					continue
				}
				filtered = append(filtered, e)
			}
			items = filtered
		}
		out := &logsOutput{}
		out.Body.Items = items
		out.Body.NextOffset = next
		return out, nil
	})
}

func entryMatches(e logstore.Entry, key, want string) bool {
	v, ok := e[key].(string)
	return ok && v == want
}

var _ = os.Getenv // keep os import if Deps changes
