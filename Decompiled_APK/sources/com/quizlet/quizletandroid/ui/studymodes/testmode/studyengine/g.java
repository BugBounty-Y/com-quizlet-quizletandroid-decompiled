package com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine;

import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final StudiableQuestion a;
    public final f b;
    public final StudiableQuestionResponse c;
    public final f d;
    public final StudiableQuestionResponse e;

    public g(StudiableQuestion studiableQuestion, f submittedAnswer, StudiableQuestionResponse studiableQuestionResponse, f expectedAnswer, StudiableQuestionResponse expectedResponse) {
        Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(expectedResponse, "expectedResponse");
        this.a = studiableQuestion;
        this.b = submittedAnswer;
        this.c = studiableQuestionResponse;
        this.d = expectedAnswer;
        this.e = expectedResponse;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c) && Intrinsics.b(this.d, gVar.d) && Intrinsics.b(this.e, gVar.e);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        StudiableQuestionResponse studiableQuestionResponse = this.c;
        return this.e.hashCode() + ((this.d.hashCode() + ((iHashCode + (studiableQuestionResponse == null ? 0 : studiableQuestionResponse.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        return "TestQuestionTuple(studiableQuestion=" + this.a + ", submittedAnswer=" + this.b + ", submittedResponse=" + this.c + ", expectedAnswer=" + this.d + ", expectedResponse=" + this.e + ")";
    }
}
