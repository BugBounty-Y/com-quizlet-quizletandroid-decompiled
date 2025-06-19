package com.quizlet.learn.ui.progress;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final int a;
    public final int b;
    public final int c;
    public final i d;
    public final Long e;
    public final com.quizlet.learn.viewmodel.k f;

    public /* synthetic */ g(int i, int i2, int i3, i iVar, int i4) {
        this(i, i2, i3, iVar, (i4 & 16) != 0 ? null : 700L, null);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && this.b == gVar.b && this.c == gVar.c && this.d == gVar.d && Intrinsics.b(this.e, gVar.e) && Intrinsics.b(this.f, gVar.f);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31)) * 31;
        Long l = this.e;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        com.quizlet.learn.viewmodel.k kVar = this.f;
        return iHashCode2 + (kVar != null ? kVar.hashCode() : 0);
    }

    public final String toString() {
        return "LearnProgressData(numCorrect=" + this.a + ", numRound=" + this.b + ", numTotal=" + this.c + ", leftPillState=" + this.d + ", delayInMs=" + this.e + ", onLeftPillAnimationFinish=" + this.f + ")";
    }

    public g(int i, int i2, int i3, i leftPillState, Long l, com.quizlet.learn.viewmodel.k kVar) {
        Intrinsics.checkNotNullParameter(leftPillState, "leftPillState");
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = leftPillState;
        this.e = l;
        this.f = kVar;
    }
}
