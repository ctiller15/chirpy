package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/ctiller15/chirpy/internal/api"
	"github.com/ctiller15/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func handleReady(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)

	apiCfg := api.NewApiConfig(dbQueries, platform, secret)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", handleReady)
	mux.HandleFunc("POST /api/users", apiCfg.HandleCreateUser)

	mux.HandleFunc("GET /api/chirps", apiCfg.HandleGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.HandleGetChirpByID)
	mux.HandleFunc("POST /api/chirps", apiCfg.HandleCreateChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.HandleDeleteChirpByID)
	mux.HandleFunc("POST /api/login", apiCfg.HandleLoginUser)
	mux.HandleFunc("POST /api/refresh", apiCfg.HandleTokenRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.HandleTokenRevoke)
	mux.HandleFunc("PUT /api/users", apiCfg.HandleUpdateUser)

	mux.HandleFunc("POST /admin/reset", apiCfg.HandleReset)
	mux.HandleFunc("GET /admin/metrics", apiCfg.HandleAdminMetrics)
	mux.Handle("/app/", apiCfg.MiddlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
