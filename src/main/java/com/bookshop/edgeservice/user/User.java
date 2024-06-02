package com.bookshop.edgeservice.user;

import java.util.List;

public record User (
        String username,
        String firstName,
        String lastName,
        String gender,
        String birthdate,
        String email,
        Boolean emailVerified,
        String job,
        Boolean isAuthor,
        List<String> roles
) {
}
