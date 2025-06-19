package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.ads.N;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q extends r {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final boolean f;
    public final boolean g;
    public final com.quizlet.assembly.widgets.progress.d h;
    public final com.quizlet.qutils.string.f i;
    public final N j;

    public q(int i, int i2, int i3, int i4, int i5, boolean z, boolean z2, com.quizlet.assembly.widgets.progress.d progressState, com.quizlet.qutils.string.f text, N summaryState) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(summaryState, "summaryState");
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
        this.f = z;
        this.g = z2;
        this.h = progressState;
        this.i = text;
        this.j = summaryState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && this.b == qVar.b && this.c == qVar.c && this.d == qVar.d && this.e == qVar.e && this.f == qVar.f && this.g == qVar.g && this.h.equals(qVar.h) && this.i.equals(qVar.i) && this.j.equals(qVar.j);
    }

    public final int hashCode() {
        return this.j.hashCode() + ((this.i.hashCode() + d0.f(d0.g(d0.g(d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31), 31), 31), 31, this.f), 31, this.g), 31, this.h.a)) * 31);
    }

    public final String toString() {
        return "Summary(cardsSize=" + this.a + ", cardsStillLearning=" + this.b + ", cardsKnown=" + this.c + ", numCardsInCycle=" + this.d + ", numCardsSeenInCycle=" + this.e + ", showConfetti=" + this.f + ", canUndo=" + this.g + ", progressState=" + this.h + ", text=" + this.i + ", summaryState=" + this.j + ")";
    }
}
