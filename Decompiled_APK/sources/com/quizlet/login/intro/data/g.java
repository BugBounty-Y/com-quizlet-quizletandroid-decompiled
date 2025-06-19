package com.quizlet.login.intro.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements j {
    public final String a;

    public g(String token) {
        Intrinsics.checkNotNullParameter(token, "token");
        this.a = token;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("SignInWithGoogle(token="), this.a, ")");
    }
}
