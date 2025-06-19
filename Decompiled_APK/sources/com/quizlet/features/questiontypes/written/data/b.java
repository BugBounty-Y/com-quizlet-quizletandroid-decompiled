package com.quizlet.features.questiontypes.written.data;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends AbstractC3455g {
    public final com.quizlet.features.infra.models.a a;
    public final com.quizlet.features.infra.models.a b;

    public b(com.quizlet.features.infra.models.a submitted, com.quizlet.features.infra.models.a expected) {
        Intrinsics.checkNotNullParameter(submitted, "submitted");
        Intrinsics.checkNotNullParameter(expected, "expected");
        this.a = submitted;
        this.b = expected;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "CloseEnough(submitted=" + this.a + ", expected=" + this.b + ")";
    }
}
