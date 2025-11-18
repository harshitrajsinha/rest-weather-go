// Package database initializes sqlite database and exposes least privilege methods
package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log"
	"time"

	"database/sql"

	_ "github.com/mattn/go-sqlite3" // Package sqlite3 provides interface to SQLite3 databases.
)

//go:embed schema.sql
var schemaFS embed.FS

// DBClient exposes restricted methods
type DBClient struct {
	db *sql.DB
}

// InitDB initializes sqlite database connection pool
func InitDB() (*DBClient, error) {

	var db *sql.DB
	var err error

	log.Println("Waiting for db startup ...")

	// Open database connection pool
	db, err = sql.Open("sqlite3", "./app.db")
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(15 * time.Minute)
	db.SetConnMaxLifetime(10 * time.Minute)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err = db.PingContext(ctxWithTimeout); err != nil {
		return nil, fmt.Errorf("error connecting to database, %w", err)
	}

	log.Println("Successfully connected to database")

	return &DBClient{db: db}, nil

}

// HealthCheck performs health check on database by ping
func (dbC *DBClient) HealthCheck() error {
	var err error
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err = dbC.db.PingContext(ctxWithTimeout); err != nil {
		return fmt.Errorf("error connecting to database, %w", err)
	}

	return nil

}

// Close closes the database connection pool
func (dbC *DBClient) Close() error {

	if err := dbC.db.Close(); err != nil {
		return fmt.Errorf("error closing database connection, %w", err)
	}
	return nil
}

// QueryRowContext fetches single row from database
func (dbC *DBClient) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return dbC.db.QueryRowContext(ctx, query, args...)
}

// QueryContext fetches single row from database
func (dbC *DBClient) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return dbC.db.QueryContext(ctx, query, args...)
}

// ExecContext executes a non-query SQL statement with context.
func (dbC *DBClient) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return dbC.db.ExecContext(ctx, query, args...)
}

// LoadDataToDatabase loads data to database via schema file
func (dbC *DBClient) LoadDataToDatabase() error {

	// Read file content
	sqlFile, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("error reading schema file, %w", err)
	}
	log.Println("...loading schema file")

	tx, err := dbC.db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction to load schema file, %w", err)
	}

	if _, err := tx.Exec(string(sqlFile)); err != nil {
		tx.Rollback()
		return fmt.Errorf("error executing schema file, %w", err)
	}

	return tx.Commit()
}

// StoreRefreshToken store refresh token in database to respective user
func (dbC *DBClient) StoreRefreshToken(refreshToken string, googleUserID string, email string) error {

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := "UPDATE users SET refresh_token=$1 WHERE google_id=$2 AND email=$3"
	result, err := dbC.db.ExecContext(ctxWithTimeout, query, refreshToken, googleUserID, email)
	if err != nil {
		return fmt.Errorf("error storing refresh token in database, %w", err)
	}

	rowAffected, _ := result.RowsAffected()
	if rowAffected == 0 {
		return errors.New("no row updated")
	}

	return nil

}
