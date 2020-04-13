package com.cybr406.account;

import com.cybr406.account.signup.SignUp;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.cybr406.account.util.TestUtil.*;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * The main goals of this homework are:
 *     * Add new @Beans to SecurityConfiguration for SignUpController & UserController
 *     * Enable method security for fine-grained control over who can modify who's profile
 *     * Create a check-user endpoint that will allow other microservices in our API to verify usernames and passwords.
 *
 * The SecurityConfiguration from the books demo will be helpful as a reference to follow:
 * https://github.com/ryl/cybr406-books-demo/blob/master/src/main/java/com/cybr406/bookdemo/SecurityConfiguration.java
 *
 * The author event handler has a good example of @PreAuthorize
 * https://github.com/ryl/cybr406-books-demo/blob/master/src/main/java/com/cybr406/bookdemo/AuthorEventHandler.java
 */
@SpringBootTest
@AutoConfigureMockMvc
public class AccountHomework02Tests {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Create JdbcUserDetailsManager bean
    @Test
    public void problem_01_configureUserDetailManagerBean() throws Exception {
        assertClassDeclaresMethod(
                "You need to create a method 'public UserDetailsManager userDetailsManager() {}'",
                "com.cybr406.account.configuration.SecurityConfiguration",
                "userDetailsManager");
        assertMethodAnnotationIsPresent(
                "You must annotate userDetailsManager() with @Bean",
                "com.cybr406.account.configuration.SecurityConfiguration",
                Bean.class,
                "userDetailsManager");
        UserDetailsManager userDetailsManager = applicationContext.getBean(UserDetailsManager.class);
        assertTrue(userDetailsManager instanceof JdbcUserDetailsManager,
                "The userDetailsManager() method should return a JdbcUserDetailsManager instance," +
                        "which is a subclass of UserDetailsManager.");
    }

    // Create PasswordEncoder bean
    @Test
    public void problem_02_configurePasswordEncoderBean() throws Exception {
        assertClassDeclaresMethod(
                "You need to create a method 'public PasswordEncoder passwordEncoder() {}'",
                "com.cybr406.account.configuration.SecurityConfiguration",
                "passwordEncoder");
        assertMethodAnnotationIsPresent(
                "You must annotate passwordEncoder() with @Bean",
                "com.cybr406.account.configuration.SecurityConfiguration",
                Bean.class,
                "passwordEncoder");
        PasswordEncoder userDetailsManager = applicationContext.getBean(PasswordEncoder.class);
        assertTrue(userDetailsManager instanceof DelegatingPasswordEncoder,
                "The passwordEncoder() method should create a password encoder using " +
                        "PasswordEncoderFactories.createDelegatingPasswordEncoder()");
    }

    // Create User.Builder bean
    @Test
    public void problem_03_configureUserBuilderBean() throws Exception {
        assertClassDeclaresMethod(
                "You need to create a method 'public User.UserBuilder userBuilder() {}'",
                "com.cybr406.account.configuration.SecurityConfiguration",
                "userBuilder");
        assertMethodAnnotationIsPresent(
                "You must annotate userBuilder() with @Bean",
                "com.cybr406.account.configuration.SecurityConfiguration",
                Bean.class,
                "userBuilder");
        User.UserBuilder userBuilder = applicationContext.getBean(User.UserBuilder.class);
        UserDetails userDetails = userBuilder.username("test").password("test").roles("TEST").build();
        assertTrue(userDetails.getPassword().startsWith("{bcrypt}"),
                "In userBuilder() make sure you call builder.passwordEncoder(...) and use the " +
                        "passwordEncoder bean to encrypt passwords");
    }

    // Enable method level security
    @Test
    public void problem_04_enableMethodLevelSecurity() {
        EnableGlobalMethodSecurity annotation = assertClassAnnotationIsPresent(
                "com.cybr406.account.configuration.SecurityConfiguration",
                EnableGlobalMethodSecurity.class
        );
        assertTrue(annotation.prePostEnabled(),
                "Set the prePostEnabled parameter of @EnableGlobalMethodSecurity to true.");
    }

    // Allow everyone to POST to /signup
    // Update SecurityConfiguration to allow everyone to POST to /signup using .permitAll()
    @Test
    public void problem_05_everyoneCanPostToSignUp() throws Exception {
        SignUp signUpA = new SignUp();
        signUpA.setUsername(UUID.randomUUID().toString());
        signUpA.setPassword("a");
        signUpA.setFirstName("a");
        signUpA.setLastName("a");
        signUpA.setInfo("a");

        // Sign up user a
        mockMvc.perform(post("/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpA)))
                .andExpect(status().isCreated());

    }

    // Prevent users from altering profiles that don't belong to them with @PreAuthorize
    @Test
    public void problem_06_onlyOwnerMayEditProfile() throws Exception {
        assertMethodAnnotationIsPresent(
                "Use @PreAuthorize on ProfileEventHandler::beforeSave to ensure only a profile's owner can edit it",
                "com.cybr406.account.ProfileEventHandler",
                PreAuthorize.class,
                "beforeSave",
                Profile.class);

        SignUp signUpA = new SignUp();
        signUpA.setUsername("a");
        signUpA.setPassword("a");
        signUpA.setFirstName("a");
        signUpA.setLastName("a");
        signUpA.setInfo("a");

        SignUp signUpB = new SignUp();
        signUpB.setUsername("b");
        signUpB.setPassword("b");
        signUpB.setFirstName("b");
        signUpB.setLastName("b");
        signUpB.setInfo("b");

        // Sign up user a
        mockMvc.perform(post("/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpA)))
                .andExpect(status().isCreated());

        // Sign up user b
        mockMvc.perform(post("/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpB)))
                .andExpect(status().isCreated());

        // Alter user a's profile as user a
        Map<String, String> patch = new HashMap<>();
        patch.put("info", "Updated by a");

        mockMvc.perform(patch("/profiles/a")
                .with(httpBasic("a", "a"))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.ALL)
                .content(objectMapper.writeValueAsString(patch)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info", equalTo("Updated by a")));

        mockMvc.perform(patch("/profiles/a")
                .with(httpBasic("b", "b"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(patch)))
                .andExpect(status().isForbidden());
    }

    // Implement UserController with checkUser method
    @Test
    public void problem_07_implementBasicCheckUserMethod() throws Exception {
        assertClassDeclaresMethod(
                "Create a method in UserController called 'checkUser' with parameters String username and String password",
                "com.cybr406.account.security.user.UserController",
                "checkUser", String.class, String.class);

        String usernameA = UUID.randomUUID().toString();
        SignUp signUpA = new SignUp();
        signUpA.setUsername(usernameA);
        signUpA.setPassword("password");
        signUpA.setFirstName(usernameA);
        signUpA.setLastName(usernameA);
        signUpA.setInfo(usernameA);

        // Sign up user_a
        mockMvc.perform(post("/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpA)))
                .andExpect(status().isCreated());

        // Simulate checking user_a's credentials on behalf of the post microservice using the post user.
        mockMvc.perform(get("/check-user")

                // Other microservices using Account to verify username/password pairs are identified by their own
                // username/password in Spring's USERS table and have the authority "ROLE_SERVICE". Make sure your
                // SecurityConfiguration class is configured to allow users with ROLE_ADMIN and ROLE_SERVICE to access
                // the /check-user URL.
                .with(httpBasic("post", "post"))

                // When another microservice asks Account to verify a username/password, they are passed along
                // to Account via headers. Make sure your checkUser method arguments are annotated with @RequestHeader
                // to map the these header values to method arguments.
                .header("x-username", usernameA)
                .header("x-password", "password"))
                .andExpect(status().isOk())
                .andExpect(content().json("[ \"ROLE_USER\" ]"));
    }

    // Verify non-existent users return BAD_REQUEST
    @Test
    public void problem_08_nonExistentUsersReturnBAD_REQUEST() throws Exception {
        mockMvc.perform(get("/check-user")
                .with(httpBasic("post", "post"))
                .header("x-username", "does-not-exist")
                .header("x-password", "does-not-exist"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(""));
    }

    // Verify wrong password returns BAD_REQUEST
    @Test
    public void problem_09_wrongPasswordsReturnBAD_REQUEST() throws Exception {
        String usernameA = UUID.randomUUID().toString();
        SignUp signUpA = new SignUp();
        signUpA.setUsername(usernameA);
        signUpA.setPassword("password");
        signUpA.setFirstName(usernameA);
        signUpA.setLastName(usernameA);
        signUpA.setInfo(usernameA);

        // Sign up user_a
        mockMvc.perform(post("/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpA)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/check-user")
                .with(httpBasic("post", "post"))
                .header("x-username", usernameA)
                .header("x-password", "wrong-password"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(""));
    }

    // Verify users with ROLE_ADMIN or ROLE_SERVICE return BAD_REQUEST.
    // We don't want to give any hint that these users & roles exist...there's no reason for anyone to fetch
    // information about these accounts unless they are up to no good.
    @Test
    public void problem_10_specialRolesReturnBAD_REQUEST() throws Exception {
        mockMvc.perform(get("/check-user")
                .with(httpBasic("post", "post"))
                .header("x-username", "post")
                .header("x-password", "post"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(""));
        mockMvc.perform(get("/check-user")
                .with(httpBasic("post", "post"))
                .header("x-username", "admin")
                .header("x-password", "admin"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(""));
    }

    // Verify only users with ROLE_ADMIN or ROLE_SERVICE can call /check-user
    @Test
    public void problem_11_onlyAdminAndServiceCanAccessCheckUser() throws Exception {
        // ROLE_USER has no hope of checking other users
        mockMvc.perform(get("/check-user")
                .with(httpBasic("user", "user"))
                .header("x-username", "anybody")
                .header("x-password", "anybody"))
                .andExpect(status().isForbidden());

        // ROLE_ADMIN can check users
        mockMvc.perform(get("/check-user")
                .with(httpBasic("admin", "admin"))
                .header("x-username", "user")
                .header("x-password", "user"))
                .andExpect(status().isOk());

        // Other microservices with ROLE_SERVICE can check users
        mockMvc.perform(get("/check-user")
                .with(httpBasic("post", "post"))
                .header("x-username", "user")
                .header("x-password", "user"))
                .andExpect(status().isOk());
    }

}
