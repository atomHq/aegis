package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/oluwasemilore/aegis/internal/config"
	"github.com/oluwasemilore/aegis/internal/handler"
	"github.com/oluwasemilore/aegis/internal/middleware"
	"github.com/oluwasemilore/aegis/internal/repository"
	"github.com/oluwasemilore/aegis/internal/server"
	"github.com/oluwasemilore/aegis/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	middleware.SetupLogger(cfg.LogLevel)
	if cfg.IsDevelopment() {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.Kitchen})
	}

	log.Info().Str("env", cfg.Env).Int("port", cfg.Port).Msg("starting aegis")

	// Configure trusted proxies for X-Forwarded-For handling
	if cfg.TrustedProxies != "" {
		var proxies []string
		for _, p := range strings.Split(cfg.TrustedProxies, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				proxies = append(proxies, p)
			}
		}
		middleware.SetTrustedProxies(proxies)
		log.Info().Strs("proxies", proxies).Msg("trusted proxies configured")
	}

	// Connect to database
	pool, err := connectDB(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	log.Info().Msg("connected to database")

	// Note: pool.Close() is registered as an OnShutdown callback below
	// so it runs in proper order during graceful shutdown (after HTTP drains)

	// Wire dependencies

	// Repositories
	tenantRepo := repository.NewPgTenantRepository(pool)
	projectRepo := repository.NewPgProjectRepository(pool)
	secretRepo := repository.NewPgSecretRepository(pool)
	apiKeyRepo := repository.NewPgAPIKeyRepository(pool)
	auditRepo := repository.NewPgAuditLogRepository(pool)
	userRepo := repository.NewPgUserRepository(pool)

	// Services
	auditSvc := service.NewAuditService(auditRepo)
	emailSvc := service.NewEmailService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom, cfg.IsDevelopment())
	tenantSvc := service.NewTenantService(tenantRepo, projectRepo, apiKeyRepo, pool)
	projectSvc := service.NewProjectService(projectRepo, tenantRepo)
	secretSvc := service.NewSecretService(secretRepo, tenantRepo, cfg.MasterKey)
	apiKeySvc := service.NewAPIKeyService(apiKeyRepo, tenantRepo)
	userSvc := service.NewUserService(userRepo, tenantRepo, projectRepo, apiKeyRepo, pool, emailSvc, cfg.JWTSecret)

	// Handlers
	healthHandler := handler.NewHealthHandler(pool)
	authHandler := handler.NewAuthHandler(userSvc, auditSvc)
	tenantHandler := handler.NewTenantHandler(tenantSvc, auditSvc)
	projectHandler := handler.NewProjectHandler(projectSvc, auditSvc)
	secretHandler := handler.NewSecretHandler(secretSvc, auditSvc)
	apiKeyHandler := handler.NewAPIKeyHandler(apiKeySvc, auditSvc)

	// Rate limiter
	rateLimiter := middleware.NewRateLimiter()

	// Parse CORS origins
	var corsOrigins []string
	for _, o := range strings.Split(cfg.CORSOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			corsOrigins = append(corsOrigins, o)
		}
	}

	// Router
	router := server.NewRouter(
		healthHandler,
		authHandler,
		tenantHandler,
		projectHandler,
		secretHandler,
		apiKeyHandler,
		auditSvc,
		apiKeySvc,
		rateLimiter,
		cfg.JWTSecret,
		tenantRepo,
		userRepo,
		corsOrigins,
	)

	// Start server
	srv := server.New(router, cfg.Port)
	srv.OnShutdown(func() {
		log.Info().Msg("closing database connection pool")
		pool.Close()
	})
	if err := srv.Start(); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}

func connectDB(cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	poolCfg.MaxConns = cfg.DBMaxConns
	poolCfg.MinConns = cfg.DBMinConns

	// Use SimpleProtocol
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}
