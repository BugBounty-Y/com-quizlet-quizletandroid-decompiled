package com.quizlet.login.login.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements k {
    public final String a;

    public i(String token) {
        Intrinsics.checkNotNullParameter(token, "token");
        this.a = token;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("SignInWithGoogle(token="), this.a, ")");
    }
}
