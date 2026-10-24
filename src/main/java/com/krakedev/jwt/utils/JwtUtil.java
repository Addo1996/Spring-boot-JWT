
package com.krakedev.jwt.utils;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class JwtUtil {

	private static final String CLAVE_SECRETA = "patitas123";

    private static final long TIEMPO_EXPIRACION = 30 * 60 * 1000;

    public static String generarToken(String username, String rol) {
        Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);

        return JWT.create()
                .withSubject(username)
                .withClaim("rol", rol)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis()
                        + TIEMPO_EXPIRACION))
                .sign(algoritmo);
    }

    public static DecodedJWT verificarToken(String token) {
        Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);

        JWTVerifier verificador = JWT.require(algoritmo).build();

        return verificador.verify(token);
    }
}
