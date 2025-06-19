package com.quizlet.quizletandroid.ui.login.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements d {
    public final com.quizlet.qutils.string.f a;

    public b(com.quizlet.qutils.string.f errorMessage) {
        Intrinsics.checkNotNullParameter(errorMessage, "errorMessage");
        this.a = errorMessage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a.equals(((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(errorMessage=" + this.a + ")";
    }
}
