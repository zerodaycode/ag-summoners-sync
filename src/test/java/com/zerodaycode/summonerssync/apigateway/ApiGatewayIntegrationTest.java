package com.zerodaycode.summonerssync.apigateway;


import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWireMock(port = 0)
class ApiGatewayIntegrationTest {

	private WireMockServer authServiceMock;
	private final WebTestClient webTestClient;

	public ApiGatewayIntegrationTest(@Autowired WebTestClient webTestClient) {
		this.webTestClient = webTestClient;
	}

	@BeforeEach
	void setup() {
		authServiceMock = new WireMockServer(8082); // Mock for auth-service
		authServiceMock.start();

		authServiceMock.stubFor(post(urlEqualTo("/auth/login"))
			.willReturn(aResponse()
				.withStatus(200)
				.withBody("{\"token\": \"fake-jwt-token\"}")
				.withHeader("Content-Type", "application/json")));
	}

	@AfterEach
	void tearDown() {
		authServiceMock.stop();
	}

	@Test
	void shouldRouteToAuthService() {
		webTestClient.post().uri("/auth/login")
			.exchange()
			.expectStatus().isOk()
			.expectHeader().contentType("application/json")
			.expectBody()
			.jsonPath("$.token").isEqualTo("fake-jwt-token");
	}
}


