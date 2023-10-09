package security.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtils {

    //инжектим поля из пропертей
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.lifetime}")
    private Duration jwtLifetime;

    //конфигуратор токена
    public String generateToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();
        //преобразовали список прав из узердетали к листу строк
        List<String> roleList = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        claims.put("roles", roleList);
        //время выпуска токена
        Date issuedDate = new Date();
        //время смерти токена
        Date expiredDate = new Date(issuedDate.getTime() + jwtLifetime.toMillis());
        //собираем токен
        return Jwts.builder()
                .setClaims(claims)                                  //основный данные
                .setSubject(userDetails.getUsername())              //имя юзера
                .setIssuedAt(issuedDate)                            //время выпуска
                .setExpiration(expiredDate)                         //время смерти
                .signWith(SignatureAlgorithm.HS256, secret)         //подпись с секретным словом
                .compact();
    }

    //достаем полезные данные из токена при помощи секретного ключа
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    //выдать имя юзера из токена
    public String getUsername(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    //выдать сприсок ролей из токена
    public List<String> getRoles(String token) {
        return getAllClaimsFromToken(token).get("roles", List.class);
    }
}
