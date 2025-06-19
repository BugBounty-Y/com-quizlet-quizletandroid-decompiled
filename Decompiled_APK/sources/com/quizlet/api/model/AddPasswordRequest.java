package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class AddPasswordRequest {

    @JsonProperty
    protected List<Data> data = new ArrayList();

    @JsonProperty
    protected Authentication authentication = new Authentication();

    public static class Authentication {

        @JsonProperty
        protected String reauthToken;
    }

    public static class Data {

        @JsonProperty
        protected String password;

        @JsonProperty
        protected String passwordConfirmation;
    }

    public AddPasswordRequest(String str, String str2, String str3) {
        Data data = new Data();
        data.password = str2;
        data.passwordConfirmation = str3;
        this.data.add(data);
        this.authentication.reauthToken = str;
    }
}
