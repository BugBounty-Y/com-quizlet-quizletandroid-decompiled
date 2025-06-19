package com.quizlet.login.intro.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements j {
    public final Throwable a;

    public h(Throwable throwable) {
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
        return "SignInWithGoogleError(throwable=" + this.a + ")";
    }
}
