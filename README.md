# Common Security

Biblioteca compartida de autenticación, autorización y filtros HTTP para servicios backend. Genera un artefacto Maven; no expone puerto ni ejecuta servidor.

## Entorno

- Java 21, Spring Boot **4.0.8** (dependencias), Maven.
- Artefacto Maven: `com.transportes:common-security:1.0-SNAPSHOT`.
- No requiere `.env`, MySQL, Eureka, Redis, Kafka ni puerto HTTP.
- El proyecto Maven reside en la raíz del repositorio (`pom.xml`, `src/`).

## Compilar e instalar

```bash
bash dev.sh build
bash dev.sh test
bash dev.sh install
```

Alternativa directa:

```bash
mvn clean install
```

La instalación coloca el JAR en el repositorio Maven local (`~/.m2/repository/com/transportes/common-security/`).

## Verificar

```bash
bash dev.sh check
```

Los logs de ejecución se guardan en `output/`. Los servicios consumidores resuelven esta dependencia mediante Maven.
