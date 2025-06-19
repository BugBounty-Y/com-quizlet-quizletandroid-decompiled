package com.google.firebase.remoteconfig;

/* loaded from: classes2.dex */
public class FirebaseRemoteConfigServerException extends FirebaseRemoteConfigException {
    public final int a;

    public FirebaseRemoteConfigServerException(int i, String str) {
        super(str);
        this.a = i;
    }

    public FirebaseRemoteConfigServerException(int i, String str, FirebaseRemoteConfigServerException firebaseRemoteConfigServerException) {
        super(str, firebaseRemoteConfigServerException);
        this.a = i;
    }

    public FirebaseRemoteConfigServerException(int i, int i2, String str) {
        super(str);
        this.a = i;
    }

    public FirebaseRemoteConfigServerException(String str) {
        super(str);
        this.a = -1;
    }
}
