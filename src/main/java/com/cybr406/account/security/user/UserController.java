package com.cybr406.account.security.user;

import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    /*
     * The job of the UserController is to receive a username and a password, and if they are correct, return the
     * authorities of the user (ROLE_ADMIN, ROLE_SERVICE, ROLE_USER, etc). This will allow other applications, such as
     * the Post application, to access this information without having their own copy of the USER's table.
     *
     * Main things you will need.
     *     * A UserDetailsManager for loading a UserDetails from the Spring Security USER table.
     *     * A PasswordEncoder for checking if the submitted password matches the hashed password.
     *
     * In the video implementation of this class, I use methods such as stream(), map(), and collect(). These might be
     * new to you. If you prefer, simple for loops can accomplish the same thing with a little more typing.
     */

}
