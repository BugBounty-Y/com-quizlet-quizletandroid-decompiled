package com.quizlet.login.login.data;

import com.facebook.FacebookException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements k {
    public final FacebookException a;

    public h(FacebookException throwable) {
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        this.a = throwable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SignInWithFacebookError(throwable=" + this.a + ")";
    }
}
