package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.google.android.gms.internal.mlkit_vision_document_scanner.f7;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends f7 {
    public final LocationQuestionSectionData b;
    public final DiagramData c;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g d;

    public p(LocationQuestionSectionData prompt, DiagramData diagramData, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g tuple) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(tuple, "tuple");
        this.b = prompt;
        this.c = diagramData;
        this.d = tuple;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.b, pVar.b) && Intrinsics.b(this.c, pVar.c) && Intrinsics.b(this.d, pVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "Location(prompt=" + this.b + ", diagramData=" + this.c + ", tuple=" + this.d + ")";
    }
}
