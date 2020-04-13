package com.cybr406.account;

import org.springframework.data.rest.core.annotation.HandleBeforeSave;
import org.springframework.data.rest.core.annotation.RepositoryEventHandler;
import org.springframework.stereotype.Component;

@Component
@RepositoryEventHandler
public class ProfileEventHandler {

    @HandleBeforeSave
    public void beforeSave(Profile profile) {
    }

}
