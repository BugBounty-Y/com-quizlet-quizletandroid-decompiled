package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.k0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3945k0 extends M0 {
    public final String a;

    public C3945k0(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof M0)) {
            return false;
        }
        return this.a.equals(((C3945k0) ((M0) obj)).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("User{identifier="), this.a, "}");
    }
}
