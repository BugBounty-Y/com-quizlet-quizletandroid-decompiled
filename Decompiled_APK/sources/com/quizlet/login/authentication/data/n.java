package com.quizlet.login.authentication.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends i {
    public final String a;

    public n(String username) {
        Intrinsics.checkNotNullParameter(username, "username");
        this.a = username;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("UsernameNotFound(username="), this.a, ")");
    }
}
