package com.furkan.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "cc644c2d2cf8e9735ad707040a8b19b6c32233f0590bc5b70f8f451891d745d1 ";

    //Jwt'den username i ayıklıyoruz gibi düşünebilirsin.
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Bu fonksiyon jwt içinden belirli bir bilgiyi (claim) çıkarmak için kullanılır.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //Token'dan gelen username ile bizdeki username'i karşılaştırıyoruz.
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()))  && isTokenExpired(token);   //Aynı ise true değil ise false dönecek.
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}



















//
//    builder() => JWT oluşturmak için bir yapı(builder) nesnesini oluşturur.
//    setClaims(extraClaims) => JWT'ye ' ekstra bilgiler eklenir bir nevi maplenir.
//    setSubject(userDetails.getUsername()) JWT'nin konusunu ayarlar bu genelde kullanıcı adı olur.
//    setIssuedAt(new Date(System.currentTimeMillis()))=>  JWT'nin milisaniye cinsinden ne zaman oluşturulduğunu yazar.
//    setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) => Token geçerlilik süresi 24 dakikadır ve her 24 dakikada bir token değişir.
////          aslında bu süre çok az olarak düşünebiliriz. Bir siteye giriş yaptığımızı düşün
//            ve 24 dakika sonra şifreni unutuyor ve bir daha şifre girmen gerekebilir
//            duruma göre kullanılır tabi ama genelde az denebilir.
//    signWith(getSignInKey(), SignatureAlgorithm.HS256) => JWT'yi imzaladık artık Algoritma yöntemi de yazar.
//    compact() => JWT'yi oluştururu ve sıkıştırılmış bir "String" formatına döner.

