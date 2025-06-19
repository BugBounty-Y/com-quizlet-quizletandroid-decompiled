package com.quizlet.api.model;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class ChangeEmailRequest {

    @JsonProperty("authentication")
    public final Authentication authentication;

    @JsonProperty("data")
    public final List<Data> data;

    public static class Authentication {

        @JsonProperty("reauthToken")
        public String reauthToken;
    }

    public static class Data {

        @JsonProperty("email")
        public String email;
    }

    public ChangeEmailRequest(@NonNull String str, @NonNull String str2) {
        ArrayList arrayList = new ArrayList();
        this.data = arrayList;
        Authentication authentication = new Authentication();
        this.authentication = authentication;
        Data data = new Data();
        data.email = str;
        arrayList.add(data);
        authentication.reauthToken = str2;
    }
}
