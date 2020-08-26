package com.tut.security.springsecuritydemo.auth;

import com.google.common.collect.Lists;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.tut.security.springsecuritydemo.security.ApplicationUserRole.*;

@Repository("fake")
@RequiredArgsConstructor
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<ApplicationUser> selectUserByUsername(String username) {
        return getApplicationUsers().stream().filter(p -> p.getUsername().equals(username)).findFirst();
    }


    // dummy users, it can be configured to get from db
    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
                new ApplicationUser("anna",
                        passwordEncoder.encode("password"),
                        STUDENT.getGrantedAuthorities(), true, true, true, true),
                new ApplicationUser("linda",
                        passwordEncoder.encode("password@123"),
                        ADMIN.getGrantedAuthorities(), true, true, true, true),
                new ApplicationUser("tom",
                        passwordEncoder.encode("password@123"),
                        ADMIN_TRAINEE.getGrantedAuthorities(), true, true, true, true)
        );
    }
}
