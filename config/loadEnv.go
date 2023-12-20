package config

import "github.com/joho/godotenv"

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		panic("Error Is Loading Env")
	}
}
