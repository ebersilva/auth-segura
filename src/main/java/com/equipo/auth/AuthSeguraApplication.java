package com.equipo.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Punto de entrada de la API de autenticación segura. */
@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthSeguraApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthSeguraApplication.class, args);
    }
}
