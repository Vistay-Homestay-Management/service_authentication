package com.vistay.authentication.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.web.client.RestClient;

class HttpClientConfigTest {

    @Test
    void providesRestClientBuilderForKeycloakAdminClient() {
        try (var context = new AnnotationConfigApplicationContext(HttpClientConfig.class)) {
            assertThat(context.getBean(RestClient.Builder.class)).isNotNull();
        }
    }
}
