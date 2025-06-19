package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements q {
    public final AssistantCheckpointProgressState a;
    public final List b;
    public final boolean c;
    public final com.quizlet.learn.ui.g d;

    public p(AssistantCheckpointProgressState progressState, List termList, boolean z, com.quizlet.learn.ui.g gVar) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(termList, "termList");
        this.a = progressState;
        this.b = termList;
        this.c = z;
        this.d = gVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return this.a == pVar.a && Intrinsics.b(this.b, pVar.b) && this.c == pVar.c && Intrinsics.b(this.d, pVar.d);
    }

    public final int hashCode() {
        int iG = d0.g(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        com.quizlet.learn.ui.g gVar = this.d;
        return iG + (gVar == null ? 0 : gVar.hashCode());
    }

    public final String toString() {
        return "Simplified(progressState=" + this.a + ", termList=" + this.b + ", canStarTerms=" + this.c + ", upsellState=" + this.d + ")";
    }
}
