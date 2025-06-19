package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h implements com.quizlet.baserecyclerview.a {
    public final b a;
    public final b b;

    public h(b firstExercise, b bVar) {
        Intrinsics.checkNotNullParameter(firstExercise, "firstExercise");
        this.a = firstExercise;
        this.b = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return -1L;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        b bVar = this.b;
        return iHashCode + (bVar == null ? 0 : bVar.hashCode());
    }

    public final String toString() {
        return "NextUpFooter(firstExercise=" + this.a + ", secondExercise=" + this.b + ")";
    }
}
