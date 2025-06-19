package com.quizlet.features.questiontypes.written.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final com.quizlet.features.questiontypes.data.d a;
    public final com.quizlet.features.questiontypes.data.b b;

    public g(com.quizlet.features.questiontypes.data.d dVar, com.quizlet.features.questiontypes.data.b bVar) {
        this.a = dVar;
        this.b = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        com.quizlet.features.questiontypes.data.d dVar = this.a;
        int iHashCode = (dVar == null ? 0 : dVar.hashCode()) * 31;
        com.quizlet.features.questiontypes.data.b bVar = this.b;
        return iHashCode + (bVar != null ? bVar.a.hashCode() : 0);
    }

    public final String toString() {
        return "WrittenQuestionState(promptState=" + this.a + ", diagramData=" + this.b + ")";
    }
}
