package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class G implements J {
    public final com.quizlet.features.practicetest.common.data.h a;

    public G(com.quizlet.features.practicetest.common.data.h reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof G) && Intrinsics.b(this.a, ((G) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(reason=" + this.a + ")";
    }
}
