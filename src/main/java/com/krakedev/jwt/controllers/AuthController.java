
package com.krakedev.jwt.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.krakedev.jwt.utils.JwtUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final UsuarioService usuarioService;

	public AuthController(UsuarioService usuarioService) {
		this.usuarioService = usuarioService;
	}

	@PostMapping("/registrar")
	public ResponseEntity<Usuario> registrar(@RequestBody Usuario usuario) {
		Usuario usuarioGuardado = usuarioService.registrar(usuario);

		return ResponseEntity.status(HttpStatus.CREATED).body(usuarioGuardado);
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Usuario datos) {
		Usuario usuario = usuarioService.login(datos.getUsername(), datos.getPassword());

		if (usuario == null) {
			Map<String, String> respuesta = new HashMap<>();
			respuesta.put("mensaje", "Usuario o contraseña incorrectos");

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(respuesta);
		}

		String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());

		Map<String, String> respuesta = new HashMap<>();
		respuesta.put("token", token);
		respuesta.put("username", usuario.getUsername());
		respuesta.put("rol", usuario.getRol());

		return ResponseEntity.ok(respuesta);
	}
	

@GetMapping("/perfil")
public ResponseEntity<?> perfil(
        @RequestHeader(value = "Authorization", required = false) String authorization) {

    if (authorization == null || !authorization.startsWith("Bearer ")) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    try {
        String token = authorization.substring(7);
        DecodedJWT jwt = JwtUtil.verificarToken(token);

        String username = jwt.getSubject();
        String rol = jwt.getClaim("rol").asString();

        Map<String, String> respuesta = new HashMap<>();
        respuesta.put("mensaje", "Bienvenido " + username);
        respuesta.put("rol", rol);

        return ResponseEntity.ok(respuesta);

    } catch (JWTVerificationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}


}
