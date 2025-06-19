package com.quizlet.learn.checkpoint.data;

import com.quizlet.studiablemodels.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final i a;
    public final boolean b;

    public d(i termShapedCard, boolean z) {
        Intrinsics.checkNotNullParameter(termShapedCard, "termShapedCard");
        this.a = termShapedCard;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && this.b == dVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SelectableTermShapedCard(termShapedCard=" + this.a + ", isSelected=" + this.b + ")";
    }
}
