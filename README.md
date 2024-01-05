# JWT (json web token)

## JWT : Header + Payload + Signature
Header(typ + alg) : 사용된 토큰 타입(typ) = JWT 및 해싱 알고리즘(alg)= HMAC SHA256, RSA... =>  {"alg":"HS256","typ":"JWT"}

PayLoad: Claim이 포함된 토큰의 두번째 부분이며 registered, public, private Claim 3가지로 구성되고 어플리케이션 데이터(사용자 ID, 이름), 토큰 만료시간, 발급자, 제목 포함
Signature: secret key를 포함하며 암호화 되어 있음


Access Token : 인증이 필요한 요청에 Access Token 사용, 일반적으로 요청헤더에 추가.


Refresh Token : 새로운 Access를 생성하고 Access token을 다시 발급 받는데 사용. Access Token이 만료되는 경우 Refresh Token을 보내서 새로운 Access Token및 Refresh Token을 생성.


JWT를 HttpOnly 쿠키에 저장하는 것을 권장. Back-end에서 생성된 쿠키를 Front-end로 보내는 동안 클라이언트측 스크립트를 통해 쿠키를 표시 않도록 부라우저에 지시하는 HttpOnly 플래그가 쿠키를 따라 전송. 