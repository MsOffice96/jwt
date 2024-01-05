package main

// https://covenant.tistory.com/203
import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"

	"github.com/google/uuid"
)

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Sample User
var user_1 = User{
	ID:       1,
	Username: "username",
	Password: "password",
}

var (
	router = gin.Default()
)

func main() {
	router.POST("/login", Login)
	router.POST("/todo", TokenAuthMiddleWare(), CreateTodo)
	router.POST("/logout", TokenAuthMiddleWare(), Logout)
	router.POST("/token/refresh", Refresh)
	log.Fatal(router.Run(":8080"))
}

func Login(c *gin.Context) {
	var u User

	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invaild json provided")
		return
	}

	if user_1.Username != u.Username || user_1.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "please provide vaild login details")
		return
	}

	// token발급
	token, err := CreateToken(user_1.ID) // JWT를 생성시 Claim에 User의 ID는 담김.
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
	}

	saveErr := CreateAuth(user_1.ID, token)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}

	user_return_token := map[string]string{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
	}

	ExtractTokenFromHeader(c.Request)

	c.JSON(http.StatusOK, user_return_token)

}

// func CreateToken(userid uint64) (string, error) {
// 	var err error
// 	os.Setenv("ACCESS_SECRET", "abcdefgh")

// 	atClaims := jwt.MapClaims{}
// 	atClaims["authorized"] = true
// 	atClaims["user_id"] = userid
// 	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

// 	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

// 	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

// 	if err != nil {
// 		return "", err
// 	}

// 	return token, nil
// 	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJleHAiOjE2NTI2ODkyMjUsInVzZXJfaWQiOjF9.q3xm_yyENXbS2ViIqthF9gG48LcuDpWyxtpCpBpAr9A

// }

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string // UUID는 Token Metadata를 Redis에 저장할때 사용
	RefreshUuid  string // UUID는 Token Metadata를 Redis에 저장할때 사용
	AtExpires    int64  // AccessToken 만료 시간
	RtExpires    int64  // RefreshToken 만료 시간
}

func CreateToken(userid uint64) (*TokenDetails, error) {
	// set ACCESS_SECRET
	os.Setenv("ACCESS_SECRET", "accesssecret")
	// set REFRES_SECRET
	os.Setenv("REFRESH_SECRET", "refresh_secret")

	token := &TokenDetails{}
	token.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	token.RtExpires = time.Now().Add(time.Minute * 60).Unix()

	token.AccessUuid = uuid.New().String()
	token.RefreshUuid = uuid.New().String()

	access_token_claim := jwt.MapClaims{}
	access_token_claim["authorized"] = true
	access_token_claim["access_uuid"] = token.AccessUuid
	access_token_claim["user_id"] = userid
	access_token_claim["exp"] = token.AtExpires

	if err := access_token_claim.Valid(); err != nil {
		log.Fatalln(err)
	}

	access_token_header_pluse_payload := jwt.NewWithClaims(jwt.SigningMethodHS256, access_token_claim)
	access_token, err := access_token_header_pluse_payload.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		log.Println(err)
	}
	log.Println("access token : ", access_token)
	token.AccessToken = access_token

	refresh_token_claim := jwt.MapClaims{}
	refresh_token_claim["refresh_uuid"] = token.RefreshUuid
	refresh_token_claim["user_id"] = userid
	refresh_token_claim["exp"] = token.RtExpires

	refresh_token_header_pluse_payload := jwt.NewWithClaims(jwt.SigningMethodHS256, refresh_token_claim)
	refresh_token, err := refresh_token_header_pluse_payload.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		log.Println(err)
	}
	log.Println("refresh token : ", refresh_token)
	token.RefreshToken = refresh_token

	return token, nil

}

var client *redis.Client

func init() {

	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6000"
	}

	client = redis.NewClient(&redis.Options{
		Addr: dsn,
	})

	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

// Save Token
func CreateAuth(userid uint64, tokendetail *TokenDetails) error {
	accesstoken_unixtime_to_utctime := time.Unix(tokendetail.AtExpires, 0)
	refreshtoken_unixtime_to_utctime := time.Unix(tokendetail.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(tokendetail.AccessUuid, strconv.Itoa(int(userid)), accesstoken_unixtime_to_utctime.Sub(now)).Err()
	log.Println("access token duration: ", accesstoken_unixtime_to_utctime.Sub(now))
	if errAccess != nil {
		return errAccess
	}

	errRefresh := client.Set(tokendetail.RefreshUuid, strconv.Itoa(int(userid)), refreshtoken_unixtime_to_utctime.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

// Fetch Auth
func FetchAuth(authAccessDetails *AccessDetail) (uint64, error) {
	userid, err := client.Get(authAccessDetails.AccessUuid).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

// Delete Ahth
func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil

}

// Extract Token from request header
func ExtractTokenFromHeader(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	log.Println("extract token from header content: ", bearToken)
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// Verify token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractTokenFromHeader(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sigining method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil

}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

type AccessDetail struct {
	AccessUuid string
	UserId     uint64
}

func ExtractTokenMetadata(r *http.Request) (*AccessDetail, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetail{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}

	return nil, err
}

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

func CreateTodo(c *gin.Context) {
	var td *Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	userId, err := FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	td.UserID = userId

	log.Printf("%+v", td)

	c.JSON(http.StatusCreated, td)
}

func Logout(c *gin.Context) {
	accessdetail, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized, ExtractTokenMetadata")
		return
	}
	deleted, delErr := DeleteAuth(accessdetail.AccessUuid)
	if delErr != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorize, DeleteAuth")
		return
	}
	c.JSON(http.StatusOK, "successfully logged out")
}

func TokenAuthMiddleWare() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		err := TokenValid(ctx.Request)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, err.Error())
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}

func Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	refreshToken := mapToken["refresh_token"]
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh tokenexpired")
		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string)
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}

		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err)
		}

		deleted, delErr := DeleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		ts, createErr := CreateToken(userId)
		if createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}

		saveErr := CreateAuth(userId, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}

		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}

}
