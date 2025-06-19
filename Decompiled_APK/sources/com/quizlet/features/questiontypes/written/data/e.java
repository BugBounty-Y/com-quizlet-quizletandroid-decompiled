package com.quizlet.features.questiontypes.written.data;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends AbstractC3455g {
    public final com.quizlet.features.infra.models.a a;
    public final com.quizlet.features.infra.models.a b;
    public final int c;

    public e(com.quizlet.features.infra.models.a submitted, com.quizlet.features.infra.models.a expected, int i) {
        Intrinsics.checkNotNullParameter(submitted, "submitted");
        Intrinsics.checkNotNullParameter(expected, "expected");
        this.a = submitted;
        this.b = expected;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && this.c == eVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Incorrect(submitted=");
        sb.append(this.a);
        sb.append(", expected=");
        sb.append(this.b);
        sb.append(", labelStringRes=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
