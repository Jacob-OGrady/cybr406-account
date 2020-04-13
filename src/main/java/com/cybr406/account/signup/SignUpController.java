package com.cybr406.account.signup;

import com.cybr406.account.Profile;
import com.cybr406.account.ProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.transaction.Transactional;
import javax.validation.Valid;

@RestController
public class SignUpController {

    @Autowired(required = false)
    private UserDetailsManager userDetailsManager;

    @Autowired(required = false)
    private ProfileRepository profileRepository;

    @Autowired(required = false)
    User.UserBuilder userBuilder;

    @Transactional
    @PostMapping("/signup")
    public ResponseEntity<Profile> signUp(@Valid @RequestBody SignUp signUp) {
        if (userDetailsManager.userExists(signUp.getUsername())) {
            throw new UsernameAlreadyExistsException(String.format(
                    "The username %s is already in use. Please choose another one.",
                    signUp.getUsername()));
        }

        userDetailsManager.createUser(userBuilder
                .username(signUp.getUsername())
                .password(signUp.getPassword())
                .roles("USER")
                .build());

        Profile profile = new Profile();
        profile.setUsername(signUp.getUsername());
        profile.setFirstName(signUp.getFirstName());
        profile.setLastName(signUp.getLastName());
        profile.setInfo(signUp.getInfo());

        return new ResponseEntity<>(profileRepository.save(profile), HttpStatus.CREATED);
    }

}
