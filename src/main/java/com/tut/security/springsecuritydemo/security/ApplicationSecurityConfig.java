package com.tut.security.springsecuritydemo.security;

import com.tut.security.springsecuritydemo.auth.ApplicationUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.TimeUnit;

import static com.tut.security.springsecuritydemo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {


    private final PasswordEncoder passwordEncoder; //must

    private final ApplicationUserService applicationUserService;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()// - is provided by spring, where CSRF token is expected from logged in user (disable for other sources than browsers)
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // by default, spring security does this,
                // if we want to implement our own logic
//                .and()
                .authorizeRequests()  // authorize
                .antMatchers("/", "index", "/css/*", "/js/*") // following are allowed - whitelisting/allow-list
                .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())  // here we are restricting access to api/** limited to STUDENT role only
/*              IMP: Following are commented because using @PreAuthorize to secure methods/APIs
                .antMatchers(POST, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(PUT, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())*/
                .anyRequest() //any request
                .authenticated() //must be authenticated
                .and()
//                .httpBasic(); //using basic
                .formLogin()
                .loginPage("/login").permitAll() // form based authentication
                .defaultSuccessUrl("/courses", true).passwordParameter("password").usernameParameter("username")
                .and()
                .rememberMe() // by default 2 weeks
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // custom validity
                .key("somethingverysecured")
                .rememberMeParameter("remember-me")
                .and()
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");

    }

    /*
    We are overriding following method to incorporate creation of user
     */

    /*@Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {
        UserDetails studentUser = User.builder()
                .username("anna")
//                .password("password") // password must be encoded // There is no PasswordEncoder mapped for the id "null"
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("passme@123"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        UserDetails adminTrainee = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("passme@123"))
//                .roles(ADMIN_TRAINEE.name())
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(studentUser, admin, adminTrainee);
    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

}
