package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func getEnvOrErr(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is not set!", key)
	}
	return value
}

func createDatabase(user string, password string, host string, port string, dbname string, sslmode string) error {
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
		return err
	}

	if !exists {
		_, err = adminConn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", dbname))
		if err != nil {
			log.Fatalf("Failed to create database: %v", err)
			return err
		}
		fmt.Printf("Database %s created successfully!\n", dbname)
	} else {
		fmt.Printf("Database %s already exists!\n", dbname)
	}
	return nil
}

func Connect(dsn string) (*gorm.DB, error) {
	var DB *gorm.DB
	var err error

	for attempts := 1; attempts <= 3; attempts++ {
		DB, err = gorm.Open(postgres.New(postgres.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		}), &gorm.Config{})

		if err == nil {
			log.Printf("Successfully connected to DB!")
			return DB, err
		}

		log.Printf("Failed to connect to database (attempt %d/3): %v", attempts, err)
		time.Sleep(3 * time.Second)
	}
	return DB, fmt.Errorf("Failed to connect to DB after 3 attempts: %w", err)
}

func AutoMigrate(DB *gorm.DB) {
	err := DB.AutoMigrate(&User{}, &GDUser{}, &Level{}, &Completion{}, &Token{})
	if err != nil {
		log.Fatalf("Failed to auto-migrate: %v", err)
	}

	log.Printf("Successfully migrated tables!")
}

var DB *gorm.DB
var DSN string

func InitDB() error {
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

	DSN = fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbname, sslmode,
	)

	if appEnv == "dev" {
		for attempts := 1; attempts <= 3; attempts++ {
			err := createDatabase(user, password, host, port, dbname, sslmode)
			if err == nil {
				break
			}
			log.Printf("DB creation failed (attempt %d/3): %v", attempts, err)
			time.Sleep(3 * time.Second)
		}
	}

	var err error
	DB, err = Connect(DSN)
	if err != nil {
		return err
	}

	AutoMigrate(DB)
	return nil
}
