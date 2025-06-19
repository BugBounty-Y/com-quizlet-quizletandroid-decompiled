package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements q {
    public final AssistantCheckpointProgressState a;
    public final int b;
    public final int c;
    public final com.quizlet.qutils.string.g d;
    public final com.quizlet.qutils.string.g e;
    public final com.quizlet.qutils.string.g f;
    public final com.quizlet.qutils.string.g g;
    public final Integer h;
    public final Integer i;
    public final Function0 j;
    public final Function0 k;
    public final List l;
    public final com.quizlet.learn.ui.g m;
    public final com.quizlet.learn.checkpoint.data.c n;
    public final boolean o;

    public n(AssistantCheckpointProgressState progressState, int i, int i2, com.quizlet.qutils.string.g header, com.quizlet.qutils.string.g message, com.quizlet.qutils.string.g primaryCtaText, com.quizlet.qutils.string.g secondaryCtaText, Integer num, Integer num2, Function0 primaryCtaClick, Function0 secondaryCtaClick, List termList, com.quizlet.learn.ui.g gVar, com.quizlet.learn.checkpoint.data.c progressBarState, boolean z) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(primaryCtaText, "primaryCtaText");
        Intrinsics.checkNotNullParameter(secondaryCtaText, "secondaryCtaText");
        Intrinsics.checkNotNullParameter(primaryCtaClick, "primaryCtaClick");
        Intrinsics.checkNotNullParameter(secondaryCtaClick, "secondaryCtaClick");
        Intrinsics.checkNotNullParameter(termList, "termList");
        Intrinsics.checkNotNullParameter(progressBarState, "progressBarState");
        this.a = progressState;
        this.b = i;
        this.c = i2;
        this.d = header;
        this.e = message;
        this.f = primaryCtaText;
        this.g = secondaryCtaText;
        this.h = num;
        this.i = num2;
        this.j = primaryCtaClick;
        this.k = secondaryCtaClick;
        this.l = termList;
        this.m = gVar;
        this.n = progressBarState;
        this.o = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return this.a == nVar.a && this.b == nVar.b && this.c == nVar.c && Intrinsics.b(this.d, nVar.d) && Intrinsics.b(this.e, nVar.e) && Intrinsics.b(this.f, nVar.f) && Intrinsics.b(this.g, nVar.g) && Intrinsics.b(this.h, nVar.h) && Intrinsics.b(this.i, nVar.i) && Intrinsics.b(this.j, nVar.j) && Intrinsics.b(this.k, nVar.k) && Intrinsics.b(this.l, nVar.l) && Intrinsics.b(this.m, nVar.m) && Intrinsics.b(this.n, nVar.n) && this.o == nVar.o;
    }

    public final int hashCode() {
        int iHashCode = (this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31)) * 31)) * 31)) * 31)) * 31;
        Integer num = this.h;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.i;
        int iF = d0.f((this.k.hashCode() + ((this.j.hashCode() + ((iHashCode2 + (num2 == null ? 0 : num2.hashCode())) * 31)) * 31)) * 31, 31, this.l);
        com.quizlet.learn.ui.g gVar = this.m;
        return Boolean.hashCode(this.o) + ((this.n.hashCode() + ((iF + (gVar != null ? gVar.hashCode() : 0)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FocusedLearnResults(progressState=");
        sb.append(this.a);
        sb.append(", roundCompleted=");
        sb.append(this.b);
        sb.append(", numTerms=");
        sb.append(this.c);
        sb.append(", header=");
        sb.append(this.d);
        sb.append(", message=");
        sb.append(this.e);
        sb.append(", primaryCtaText=");
        sb.append(this.f);
        sb.append(", secondaryCtaText=");
        sb.append(this.g);
        sb.append(", primaryCtaIconRes=");
        sb.append(this.h);
        sb.append(", secondaryCtaIconRes=");
        sb.append(this.i);
        sb.append(", primaryCtaClick=");
        sb.append(this.j);
        sb.append(", secondaryCtaClick=");
        sb.append(this.k);
        sb.append(", termList=");
        sb.append(this.l);
        sb.append(", upsellState=");
        sb.append(this.m);
        sb.append(", progressBarState=");
        sb.append(this.n);
        sb.append(", canStarTerms=");
        return android.support.v4.media.session.a.o(")", sb, this.o);
    }
}
