# JWT (json web token)

## JWT : Header + Payload + Signature
* Header(typ + alg) : 사용된 토큰 타입(typ) = JWT 및 해싱 알고리즘(alg)= HMAC SHA256, RSA... => encoding base64 {"alg":"HS256","typ":"JWT"}
    * typ: 사용된 토큰 타입(JWT)
    * alg: 해싱 알고리증(HMAC SHA256, RSA ...)
* PayLoad: Claim이 포함된 토큰의 두번째 부분이며 registered, public, private Claim 3가지로 구성
    * registered
        * iss: 토큰 발급자(issuer)
        * sub: 토근 제목(subject)
        * aud: 토근 대상자(audience)
        * exp: 토큰 만료시간(expiraton), 시간은 NumericDate 형식으로 되어있어야 하며 언제나 현재 시간 보다 이후로 설정되어 있어야한다.
        * nbg: Not Before을 의미하며 토튼의 활성 날짜와 비슷함. 이 날짝가 지나기 전에는 토큰이 처리 되지않는다.
        * iat: 토큰이 발급된 시간(issued at), 이 값을 사용하여 토큰의 age가 얼마나 되었는지 판단 할 수 있다.
        * jti: JWT의 고유 식별자로사, 주로 중복적인 처리를 방지하기 위하여 사용되며 일회용 토큰에 사용하면 유용함
    * public: 충돌이 방지된(collison-resistant)이름을 가지고 있어야 되며 충돌을 방지하기 위하여 클레임 이름을 URI 형식으로 한다
    * Private: 클라이언트와 서버 협의하에 사용되는 클레임 이름이다.
* Signature: secret key를 포함하며 Secret Key로 암호화 되어 있음  

## Access Token & Refresh token
Access Token : 인증이 필요한 요청에 Access Token 사용, 일반적으로 요청헤더에 추가.  
Refresh Token : 새로운 Access token을 생성하고 Access token을 다시 발급 받는데 사용. Access Token이 만료되는 경우 Refresh Token을 보내서 새로운 Access Token및 Refresh Token을 생성.  
JWT를 HttpOnly 쿠키에 저장하는 것을 권장. Back-end에서 생성된 쿠키를 Front-end로 보내는 동안 클라이언트측 스크립트를 통해 쿠키를 표시 않도록 부라우저에 지시하는 HttpOnly 플래그가 쿠키를 따라 전송.  

처음 사용자를 등록할 때 Access Token과 Refresh Token 이 모두 발급되어야 되며 Token은 브라우저의 localStorage 또는 Session Storage 또는 쿠키에 담아서 사용가능.

## Authentication 과정
1. 사용자가 Id와 Password를 입력하여 로그인은 시도.
2. 서버는 요청을 확인하여 Secret Key를 통하여 Access Token 발급 및 사용자에게 전달.
3. 클라이언트에서 API를 요청할때 Authorization Header에 Access Token을 포함.
4. 서버는 JWT Signature를 체크하고 PayLoad로 부터 사용자의 정보를 확인하여 데이터를 반환.
5. 클라이언트의 로그인 정보를 서버 메모리에 저장하지 않기 때문에 토근기반 인증 메커니즘을 제공한다.