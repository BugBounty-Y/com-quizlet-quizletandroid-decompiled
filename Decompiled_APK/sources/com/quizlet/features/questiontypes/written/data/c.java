package com.quizlet.features.questiontypes.written.data;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC3455g {
    public final com.quizlet.features.infra.models.a a;
    public final int b;

    public c(com.quizlet.features.infra.models.a submitted, int i) {
        Intrinsics.checkNotNullParameter(submitted, "submitted");
        this.a = submitted;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Correct(submitted=" + this.a + ", labelStringRes=" + this.b + ")";
    }
}
