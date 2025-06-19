package com.quizlet.features.questiontypes.written.data;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import com.quizlet.features.questiontypes.written.ui.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends AbstractC3455g {
    public final i a;
    public final Integer b;

    public f(i responseState, Integer num) {
        Intrinsics.checkNotNullParameter(responseState, "responseState");
        this.a = responseState;
        this.b = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "Input(responseState=" + this.a + ", labelStringRes=" + this.b + ")";
    }
}
