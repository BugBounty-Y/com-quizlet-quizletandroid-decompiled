package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class g {

    @NonNull
    private final String a;

    @NonNull
    private final String b;
    private int c = 0;
    private JSONObject d;

    public g(@NonNull String str, @NonNull String str2) {
        this.a = str;
        this.b = str2;
    }

    public int getAtype() {
        return this.c;
    }

    public JSONObject getExtension() {
        return this.d;
    }

    @NonNull
    public String getId() {
        return this.b;
    }

    @NonNull
    public String getSource() {
        return this.a;
    }

    public void setAtype(int i) {
        this.c = i;
    }

    public void setExtension(JSONObject jSONObject) {
        this.d = jSONObject;
    }
}
