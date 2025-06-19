package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3931d0 extends G0 {
    public final String a;

    public C3931d0(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof G0)) {
            return false;
        }
        return this.a.equals(((C3931d0) ((G0) obj)).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Log{content="), this.a, "}");
    }
}
