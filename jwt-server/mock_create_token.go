package main

// type TokenDetails struct {
// 	AccessToken  string
// 	RefreshToken string
// 	AccessUuid   string // UUID는 Token Metadata를 Redis에 저장할때 사용
// 	RefreshUuid  string // UUID는 Token Metadata를 Redis에 저장할때 사용
// 	AtExpires    int64  // AccessToken 만료 시간
// 	RtExpires    int64  // RefreshToken 만료 시간
// }

// token := &TokenDetails{}
// 	token.AtExpires = time.Now().Add(time.Minute * 15).Unix()
// 	token.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()

// 	token.AccessUuid = uuid.New().String()
// 	token.RefreshUuid = uuid.New().String()

// 	// os.Setenv("ACCESS_SECRET", "access_secret")
// 	// os.Setenv("REFRESH_SECRET", "refresh_secret")
// 	os.Setenv("ACCESS_SECRET", "access_secret")
// 	os.Setenv("REFRESH_SECRET", "refresh_secret")

// 	access_token_claim := jwt.MapClaims{}
// 	access_token_claim["authorized"] = true
// 	access_token_claim["access_uuid"] = token.AccessUuid
// 	access_token_claim["user_id"] = userid
// 	access_token_claim["exp"] = token.AtExpires

// 	access_token_header_pluse_payload := jwt.NewWithClaims(jwt.SigningMethodES256, access_token_claim)
// 	access_token, err := access_token_header_pluse_payload.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
// 	if err != nil {
// 		log.Fatalln(err)
// 		return nil, err
// 	}
// 	token.AccessToken = access_token

// 	refresh_token_claim := jwt.MapClaims{}
// 	refresh_token_claim["refresh_uuid"] = token.RefreshUuid
// 	refresh_token_claim["user_id"] = userid
// 	refresh_token_claim["exp"] = token.RtExpires

// 	refresh_token_header_pluse_payload := jwt.NewWithClaims(jwt.SigningMethodES256, refresh_token_claim)
// 	refresh_token, err := refresh_token_header_pluse_payload.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
// 	if err != nil {
// 		return nil, err
// 	}
// 	token.RefreshToken = refresh_token

// 	return token, nil
