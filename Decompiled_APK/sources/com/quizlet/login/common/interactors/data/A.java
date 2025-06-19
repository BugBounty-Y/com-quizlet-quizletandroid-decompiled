package com.quizlet.login.common.interactors.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements C {
    public final com.quizlet.qutils.string.f a;

    public A(com.quizlet.qutils.string.f error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A) && this.a.equals(((A) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(error=" + this.a + ")";
    }
}
