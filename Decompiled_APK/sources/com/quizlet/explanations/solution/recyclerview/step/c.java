package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final String a;
    public boolean b;
    public final d c;

    public c(String text, boolean z, d dVar) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = z;
        this.c = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        d dVar = this.c;
        return iG + (dVar == null ? 0 : dVar.hashCode());
    }

    public final String toString() {
        return "SolutionStepColumn(text=" + this.a + ", hasValidKatex=" + this.b + ", images=" + this.c + ")";
    }
}
