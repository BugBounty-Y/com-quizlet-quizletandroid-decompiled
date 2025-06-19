package com.quizlet.features.notes.detail.states;

import com.quizlet.features.notes.data.x;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements h {
    public final x a;

    public e(x reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(reason=" + this.a + ")";
    }
}
