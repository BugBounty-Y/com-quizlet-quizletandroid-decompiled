package com.quizlet.features.practicetest.results.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements w {
    public final com.quizlet.features.practicetest.common.data.h a;

    public u(com.quizlet.features.practicetest.common.data.h reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && Intrinsics.b(this.a, ((u) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(reason=" + this.a + ")";
    }
}
