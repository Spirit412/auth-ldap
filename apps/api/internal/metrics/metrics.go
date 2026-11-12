// Package metrics defines Prometheus instruments (F-09): login/refresh
// counters with outcomes and operation latency histograms.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	LoginAttempts *prometheus.CounterVec   // result=success|invalid_credentials|rate_limited|error
	LoginDuration prometheus.Histogram     // seconds
	RefreshTotal  *prometheus.CounterVec   // result=success|replay|invalid|rate_limited|error
	LDAPDuration  *prometheus.HistogramVec // op=authenticate|ping|refresh_roles
	HTTPRequests  *prometheus.CounterVec   // method,route,code
	HTTPDuration  *prometheus.HistogramVec // method,route
}

func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	return &Metrics{
		LoginAttempts: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "aps",
			Name:      "login_attempts_total",
			Help:      "Login attempts by outcome.",
		}, []string{"result"}),
		LoginDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Namespace: "aps",
			Name:      "login_duration_seconds",
			Help:      "Login endpoint latency.",
			Buckets:   prometheus.DefBuckets,
		}),
		RefreshTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "aps",
			Name:      "refresh_total",
			Help:      "Refresh rotations by outcome.",
		}, []string{"result"}),
		LDAPDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "aps",
			Name:      "ldap_operation_duration_seconds",
			Help:      "LDAP operation latency.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"op"}),
		HTTPRequests: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "aps",
			Name:      "http_requests_total",
			Help:      "HTTP requests handled.",
		}, []string{"method", "route", "code"}),
		HTTPDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "aps",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
}
