package com.quizlet.features.questiontypes.composables;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final int a;
    public final Function0 b;

    public d(int i, Function0 onClick) {
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = i;
        this.b = onClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ContinueState(textStringRes=" + this.a + ", onClick=" + this.b + ")";
    }
}
