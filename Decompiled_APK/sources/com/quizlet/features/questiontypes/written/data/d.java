package com.quizlet.features.questiontypes.written.data;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends AbstractC3455g {
    public final com.quizlet.features.infra.models.a a;

    public d(com.quizlet.features.infra.models.a expected) {
        Intrinsics.checkNotNullParameter(expected, "expected");
        this.a = expected;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DoNotKnow(expected=" + this.a + ")";
    }
}
