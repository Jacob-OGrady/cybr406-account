package com.cybr406.account;

import org.hibernate.annotations.Type;
import org.hibernate.validator.constraints.Length;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Entity
public class Profile {

    @Id
    @NotBlank
    @Length(max = 50)
    @Pattern(regexp = "[a-zA-Z0-9_\\-]+", message = "Usernames may only consist of letters, numbers, underscores, and dashes.")
    private String username;

    @NotBlank
    @Length(max = 50)
    private String firstName;

    @NotBlank
    @Length(max = 50)
    private String lastName;

    @Lob
    @Type(type = "org.hibernate.type.TextType")
    private String info;

    public Profile() {}

    public Profile(@Length(max = 50) @NotBlank String username, @NotNull @NotBlank @Length(max = 50) String firstName, @NotNull @NotBlank @Length(max = 50) String lastName, String info) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.info = info;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

}
