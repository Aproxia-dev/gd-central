package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("couldn't find .env file! using system variables instead")
	}

	user := getEnvOrErr("PGUSER")
	password := getEnvOrErr("PGPASSWORD")
	host := getEnvOrErr("PGHOST")
	port := getEnvOrErr("PGPORT")
	dbname := getEnvOrErr("PGDATABASE")
	sslmode := os.Getenv("PGSSLMODE")
	if sslmode == "" {
		sslmode = "disable"
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
