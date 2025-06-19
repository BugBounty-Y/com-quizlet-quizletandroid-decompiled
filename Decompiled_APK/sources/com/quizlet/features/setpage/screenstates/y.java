package com.quizlet.features.setpage.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y extends A {
    public final com.quizlet.qutils.string.f a;

    public y(com.quizlet.qutils.string.f confirmTitle) {
        Intrinsics.checkNotNullParameter(confirmTitle, "confirmTitle");
        this.a = confirmTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && this.a.equals(((y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ResetProgress(confirmTitle=" + this.a + ")";
    }
}
