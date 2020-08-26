package com.tut.security.springsecuritydemo.auth;

import java.util.Optional;

public interface ApplicationUserDAO {
    Optional<ApplicationUser> selectUserByUsername(String username);
}
