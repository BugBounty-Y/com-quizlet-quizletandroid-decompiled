package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements A {
    public final AbstractC4540e a;
    public final boolean b;
    public final com.quizlet.learn.ui.g c;

    public y(AbstractC4540e endState, boolean z, com.quizlet.learn.ui.g gVar) {
        Intrinsics.checkNotNullParameter(endState, "endState");
        this.a = endState;
        this.b = z;
        this.c = gVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.a, yVar.a) && this.b == yVar.b && Intrinsics.b(this.c, yVar.c);
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        com.quizlet.learn.ui.g gVar = this.c;
        return iG + (gVar == null ? 0 : gVar.hashCode());
    }

    public final String toString() {
        return "Content(endState=" + this.a + ", shouldShowUpsell=" + this.b + ", upsellState=" + this.c + ")";
    }
}
