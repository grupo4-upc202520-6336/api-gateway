package com.agrocontrol.apigateway.infrastructure.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Filtro de Seguridad Global para el API Gateway.
 * Intercepta todas las peticiones HTTP entrantes para validar el Token JWT.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    // Inyectamos la clave secreta desde application.yml
    // Debe ser EXACTAMENTE la misma que usa tu iam-service
    @Value("${authorization.jwt.secret}")
    private String secret;

    // Lista de rutas públicas que NO necesitan token (Login, Registro, Swagger)
    // Estas rutas se saltarán la validación de seguridad.
    private final List<String> publicPaths = List.of(
            "/api/v1/authentication/sign-in",
            "/api/v1/authentication/sign-up",
            "/v3/api-docs",
            "/swagger-ui",
            "/swagger-resources",
            "/webjars"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 1. VALIDACIÓN DE RUTAS PÚBLICAS
        // Si la ruta es pública (ej. login), dejamos pasar la petición sin revisar nada.
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // 2. OBTENER EL HEADER 'AUTHORIZATION'
        // Buscamos la cabecera que debe contener "Bearer eyJhbGci..."
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Si no hay token o no tiene el formato correcto, rechazamos la petición (401)
            return onError(exchange, "Falta el encabezado de autorización o es inválido", HttpStatus.UNAUTHORIZED);
        }

        // 3. VALIDAR EL TOKEN
        // Extraemos el token puro (quitando el "Bearer ")
        String token = authHeader.substring(7);

        try {
            // Preparamos la llave para desencriptar
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

            // Intentamos abrir y leer el token
            Claims claims = Jwts.parser()
                    .verifyWith(key) // Verificamos la firma con nuestra clave secreta
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Si llegamos aquí, el token es válido.
            // Extraemos el ID del usuario (el "subject" del token)
            String userId = claims.getSubject();

            // 4. INYECCIÓN DE CABECERA (LA MAGIA)
            // Modificamos la petición para agregar una cabecera interna 'X-User-ID'.
            // Los microservicios (Store, Profile) leerán esta cabecera para saber quién es el usuario.
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-ID", userId) // <-- Aquí pasamos el ID
                    .build();

            // Pasamos la petición modificada al siguiente eslabón de la cadena (el microservicio destino)
            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            // Si el token expiró, la firma está mal, o fue modificado: ERROR 401.
            System.err.println("Error validando token: " + e.getMessage());
            return onError(exchange, "Token inválido o expirado", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Verifica si la ruta actual coincide con alguna de las rutas públicas.
     */
    private boolean isPublicPath(String path) {
        return publicPaths.stream().anyMatch(path::startsWith);
    }

    /**
     * Método helper para devolver una respuesta de error HTTP y detener la cadena.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        // Opcional: Podrías escribir un mensaje de error en el cuerpo de la respuesta aquí si quisieras
        return exchange.getResponse().setComplete();
    }

    /**
     * Define la prioridad del filtro.
     * -1 significa que tiene una prioridad muy alta y se ejecutará antes que la mayoría de filtros.
     */
    @Override
    public int getOrder() {
        return -1;
    }
}

