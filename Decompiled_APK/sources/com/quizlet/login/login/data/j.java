package com.quizlet.login.login.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements k {
    public final Throwable a;

    public j(Throwable throwable) {
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        this.a = throwable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && Intrinsics.b(this.a, ((j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SignInWithGoogleError(throwable=" + this.a + ")";
    }
}
