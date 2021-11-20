package db

import (
	"auth_service/pkg/models"
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type MongoDBTempDAO struct {
	db             *mongo.Database
	userCollection string
}

func NewMongoDBTemp(ctx context.Context, db *mongo.Database) *MongoDBTempDAO {
	return &MongoDBTempDAO{db: db, userCollection: "users"}
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func (dao *MongoDBTempDAO) FindUser(ctx context.Context, username string, password string) (bool, error) {
	collection := dao.db.Collection("users")
	curr, err := collection.Find(ctx, bson.M{"username": username})
	var usr models.UserDB
	var res []models.UserDB

	if err != nil {
		return false, fmt.Errorf("no user: %w", err)
	}

	for curr.Next(context.TODO()) {

		err = curr.Decode(&usr)
		if err != nil {
			return false, fmt.Errorf("cannot decode user: %w", err)
		}
		fmt.Println(usr)
		res = append(res, usr)
	}
	fmt.Println(res)
	if len(res) == 0 {
		return false, fmt.Errorf("cannot decode user: %w", "no user")
	}
	isUser := CheckPasswordHash(password, res[0].Password)
	return isUser, nil
}
