package com.vistay.authentication.adapter.in.rest;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceInfoControllerTest {

    @Test
    void exposesStableServiceIdentity() {
        var info = new ServiceInfoController().serviceInfo();

        assertThat(info).containsEntry("name", "authentication");
        assertThat(info).containsEntry("version", "0.1.0");
    }
}
