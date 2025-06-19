package com.google.firebase.sessions.dagger.internal;

/* loaded from: classes2.dex */
public final class c implements b, com.google.firebase.sessions.dagger.a {
    public final Object a;

    public c(Object obj) {
        this.a = obj;
    }

    public static c a(Object obj) {
        if (obj != null) {
            return new c(obj);
        }
        throw new NullPointerException("instance cannot be null");
    }

    @Override // javax.inject.a
    public final Object get() {
        return this.a;
    }
}
