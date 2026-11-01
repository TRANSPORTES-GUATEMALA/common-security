# Common Security

Biblioteca Maven para autenticación JWT y autorización por rol en servicios Spring MVC/Servlet. Se autoconfigura desde `AutoConfiguration.imports`; no inicia servidor ni implementa login, emisión de tokens, identidad activa, titularidad o autorización por sucursal. No se activa en aplicaciones WebFlux.

## Entorno y consumo

- Java 21 y Spring Boot 4.0.8.
- Artefacto: `com.transportes:common-security:1.0-SNAPSHOT`.
- El consumidor Servlet proporciona `spring-boot-starter-webmvc`, `spring-boot-starter-security` y `spring-boot-starter-aop`; esas dependencias se declaran `provided` en esta biblioteca.
- JJWT API queda en compile y sus módulos `jjwt-impl`/`jjwt-jackson` en runtime.
- No requiere `.env`, MySQL, Eureka, Redis, Kafka ni puerto HTTP.
- El proyecto Maven reside en la raíz (`pom.xml`, `src/`).

## Configuración

La clave `security.jwt.secret-key` debe ser Base64 y decodificar a una clave HMAC válida. No la guardes en el repositorio.

```yaml
security:
  jwt:
    secret-key: ${SECURITY_JWT_SECRET_KEY}
  public:
    routes:
      - POST:/api/v1/auth/login
```

No hay rutas públicas por defecto. Cada excepción requiere `MÉTODO:/ruta`; por ejemplo, configura solo las operaciones de registro, login, confirmación de email o A2F que ese servicio realmente exponga. También configura rutas concretas de health o documentación cuando hagan falta. Se admiten segmentos `*` y un `**` final; una regla nula, malformada o demasiado amplia como `/**` se ignora y la ruta permanece protegida.

El interceptor aplica a `/api/v1/**`, `/v1/**` e `/internal/v1/**`. Las rutas internas siempre requieren JWT `SERVICE`, aunque una regla pública coincida. Fuera de esos prefijos, la cadena de seguridad deniega por defecto y solo permite rutas configuradas explícitamente.

## JWT y autorización

- USER acepta el formato actual firmado con `sub`, `userId`, `roles`, `iat` y `exp`, sin exigir `type: USER`; también acepta `type: USER` explícito. `userId` debe ser numérico positivo y `roles` una lista de textos. La biblioteca no convierte claims ni headers `X-User-*`/`X-Roles` en identidad.
- SERVICE requiere `sub`, `type: SERVICE`, `iat` y `exp`. No recibe atributos ni roles de usuario; un token de usuario, incluso ADMIN, obtiene `403` en `/internal/v1/**`.
- La firma, expiración e identidad se validan antes de establecer atributos. En solicitudes verificadas, se preservan `userId` y `roles` para USER; `authType` distingue `USER`/`SERVICE` y `service` identifica al servicio.
- `@RequireRole` y `RoleAspect` conservan sus firmas. Sin identidad verificada se responde `401`; un rol insuficiente o un servicio intentando una operación de usuario responde `403`. Titularidad y sucursal corresponden al servicio dueño del recurso.
- Los rechazos de autenticación/autorización que genera esta biblioteca devuelven `application/json;charset=UTF-8` con `code`, `message` y `correlationId`. Los códigos son `AUTH_UNAUTHORIZED` (`401`) y `AUTH_FORBIDDEN` (`403`); los mensajes no exponen detalles del parser. Se reutiliza el atributo Servlet confiable `correlationId` si contiene un valor seguro; si no existe, se genera un UUID. No se refleja `X-Correlation-Id` enviado por el cliente.

## Compilar, probar e instalar

```bash
bash dev.sh build
bash dev.sh test
bash dev.sh install
bash dev.sh check
```

`install` coloca el JAR `1.0-SNAPSHOT` en el repositorio Maven local; no actualiza consumidores ni acredita su integración. `check` solo comprueba el JAR. La suite MockMvc carga la autoconfiguración por metadata y cubre JWT, rutas, roles y estados HTTP.
