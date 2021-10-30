package database

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
)

type Config struct {
	DBName  string
	ConnStr string
}

type Database struct {
	db             *mongo.Database
	client         *mongo.Client
	userCollection *mongo.Collection
}

func NewDatabase(ctx context.Context, config *Config) (*Database, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(config.ConnStr))
	if err != nil {
		log.Fatal("mongo client creation:", err)
	}
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal("mongo client connection:", err)
	}
	db := client.Database(config.DBName)
	userCollection := db.Collection("user")

	return &Database{
		db:             db,
		client:         client,
		userCollection: userCollection,
	}, nil
}

func (d *Database) Ping(ctx context.Context) error {
	return d.client.Ping(ctx, readpref.Primary())
}

func (d *Database) Close(ctx context.Context) error {
	return d.client.Disconnect(ctx)
}
