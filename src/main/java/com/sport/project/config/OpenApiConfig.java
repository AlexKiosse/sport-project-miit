package com.sport.project.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Конфигурация OpenAPI Swagger документации
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Sport Project API")
                        .version("0.1.0")
                        .description("API для управления спортивными занятиями в университете: " +
                                "учёт студентов, преподавателей, групп, дисциплин, занятий и посещаемости"))
                .servers(List.of(
                        new Server()
                                .url("/")
                                .description("Local Development Server")
                ));
    }
}
