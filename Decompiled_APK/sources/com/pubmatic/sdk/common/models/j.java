package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class j {

    @NonNull
    private final String a;
    private String b;
    private String c;

    public j(@NonNull String str) {
        this.a = str;
    }

    public String getName() {
        return this.b;
    }

    @NonNull
    public String getSegId() {
        return this.a;
    }

    public String getValue() {
        return this.c;
    }

    public void setValue(@NonNull String str) {
        this.c = str;
    }

    public j(@NonNull String str, @NonNull String str2) {
        this.a = str;
        this.b = str2;
    }
}
