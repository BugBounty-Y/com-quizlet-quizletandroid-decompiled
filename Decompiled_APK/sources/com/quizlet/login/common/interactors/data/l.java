package com.quizlet.login.common.interactors.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends z {
    public final com.quizlet.login.authentication.data.b a;

    public l(com.quizlet.login.authentication.data.b response) {
        Intrinsics.checkNotNullParameter(response, "response");
        this.a = response;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && Intrinsics.b(this.a, ((l) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ApiThreeError(response=" + this.a + ")";
    }
}
