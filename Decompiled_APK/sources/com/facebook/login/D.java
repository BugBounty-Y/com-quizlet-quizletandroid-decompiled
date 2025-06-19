package com.facebook.login;

/* loaded from: classes.dex */
public enum D {
    FACEBOOK("facebook"),
    INSTAGRAM("instagram");

    public final String a;

    D(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
