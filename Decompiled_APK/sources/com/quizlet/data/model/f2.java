package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f2 extends h2 {
    public final Exception a;

    public f2(Exception exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f2) && Intrinsics.b(this.a, ((f2) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "StudyStreakException(exception=" + this.a + ")";
    }
}
