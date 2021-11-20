package db

import (
	"auth_service/pkg/conf"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

type MongoDBTemplateDAO struct {
	db                 *mongo.Database
	templateCollection string
	opt                *options.ClientOptions
}

var mongoDBConnection *mongo.Database
var optionsDB *options.ClientOptions

func NewMongoDBTemplateDAO(ctx context.Context, db *mongo.Database) *MongoDBTemplateDAO {
	return &MongoDBTemplateDAO{db: db, templateCollection: "users", opt: optionsDB}
}
func ConnectMongoDB(ctx context.Context, config *conf.Config) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	optionsDB = options.Client().ApplyURI(config.DatabaseUri)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(config.DatabaseUri))
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	mongoDBConnection = client.Database(config.DBname)
	log.Println("Connection to DB success")
}

func GetMongoDBConnection() *mongo.Database {
	return mongoDBConnection
}
