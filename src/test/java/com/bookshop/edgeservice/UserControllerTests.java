package com.bookshop.edgeservice;

import com.bookshop.edgeservice.config.SecurityConfig;
import com.bookshop.edgeservice.user.User;
import com.bookshop.edgeservice.user.UserController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@WebFluxTest(UserController.class)
@Import(SecurityConfig.class)
public class UserControllerTests {

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Test
    void whenNotAuthenticatedThenReturn401() {
        webTestClient
                .get()
                .uri("/user")
                .exchange()
                .expectStatus().is3xxRedirection();
    }

    @Test
    void whenAuthenticatedThenReturnUser() {
        var expectedUser = new User("thainguyen", "Nguyen",
                "Thai", List.of("employee", "customer"));

        webTestClient
                .mutateWith(configureMockOidcLogin(expectedUser))
                .get()
                .uri("/user")
                .exchange()
                .expectStatus().is2xxSuccessful()
                .expectBody(User.class)
                .value(user -> assertThat(user).isEqualTo(expectedUser));
    }

    private SecurityMockServerConfigurers.OidcLoginMutator configureMockOidcLogin(
            User expectedUser
    ) {
        return SecurityMockServerConfigurers.mockOidcLogin()
                .idToken(builder -> builder
                        .claim(StandardClaimNames.PREFERRED_USERNAME, expectedUser.username())
                        .claim(StandardClaimNames.GIVEN_NAME, expectedUser.firstName())
                        .claim(StandardClaimNames.FAMILY_NAME, expectedUser.lastName())
                        .claim("roles", expectedUser.roles())
                );
    }

}
