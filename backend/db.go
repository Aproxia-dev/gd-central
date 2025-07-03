package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	// "github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex"`
	Email    string `gorm:"uniqueIndex"`
}

func getEnvOrErr(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is not set!", key)
	}
	return value
}

func createDatabase(user string, password string, host string, port string, dbname string, sslmode string) {
	adminUrl := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/postgres?sslmode=%s",
		user, password, host, port, sslmode,
	)
	ctx := context.Background()
	adminConn, err := pgx.Connect(ctx, adminUrl)
	if err != nil {
		log.Fatalf("Failed to connect to admin DB: %v", err)
	}

	defer adminConn.Close(ctx)

	var exists bool
	err = adminConn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 from pg_database WHERE datname = $1)", dbname).Scan(&exists)
	if err != nil {
		log.Fatalf("Failed to check database existence: %v", err)
	}

	if !exists {
		_, err = adminConn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", dbname))
		if err != nil {
			log.Fatalf("Failed to create database: %v", err)
		}
		fmt.Printf("Database %s created successfully!\n", dbname)
	} else {
		fmt.Printf("Database %s already exists!\n", dbname)
	}
}

func main() {
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Println("couldn't find .env file! using system variables instead")
	// }

	appEnv := os.Getenv("APP_ENV")
	user := getEnvOrErr("PGUSER")
	password := getEnvOrErr("PGPASSWORD")
	host := getEnvOrErr("PGHOST")
	port := getEnvOrErr("PGPORT")
	dbname := getEnvOrErr("PGDATABASE")
	sslmode := os.Getenv("PGSSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	if appEnv == "dev" {
		createDatabase(user, password, host, port, dbname, sslmode)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbname, sslmode,
	)

	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatalf("Failed to auto-migrate: %v", err)
	}

	fmt.Println("Successfully connected to database and migrated User table!")
}
