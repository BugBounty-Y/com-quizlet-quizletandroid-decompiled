package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.google.android.gms.internal.mlkit_vision_document_scanner.e7;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends e7 {
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b;
    public final DiagramData c;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f d;
    public final StudiableQuestion e;

    public m(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f expectedAnswer, DiagramData diagramData, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f submittedAnswer, StudiableQuestion studiableQuestion) {
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
        this.b = expectedAnswer;
        this.c = diagramData;
        this.d = submittedAnswer;
        this.e = studiableQuestion;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f a() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.b, mVar.b) && Intrinsics.b(this.c, mVar.c) && Intrinsics.b(this.d, mVar.d) && Intrinsics.b(this.e, mVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Diagram(expectedAnswer=" + this.b + ", diagramData=" + this.c + ", submittedAnswer=" + this.d + ", studiableQuestion=" + this.e + ")";
    }
}
