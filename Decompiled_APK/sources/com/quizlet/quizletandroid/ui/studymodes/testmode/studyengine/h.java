package com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.k7;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.grading.MultipleChoiceResponse;
import com.quizlet.studiablemodels.grading.StudiableQuestionFeedback;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import com.quizlet.studiablemodels.grading.StudiableTestResults;
import com.quizlet.studiablemodels.grading.TrueFalseResponse;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final Long a;
    public final String b;
    public final StudiableTestResults c;
    public final ArrayList d;
    public final int e;
    public final int f;
    public final StudiableMeteringData g;
    public final double h;
    public final StudiableMeteringData i;
    public final ArrayList j;

    public h(Long l, String str, StudiableTestResults results, ArrayList questions, int i, int i2, StudiableMeteringData studiableMeteringData) {
        f fVar;
        Intrinsics.checkNotNullParameter(results, "results");
        Intrinsics.checkNotNullParameter(questions, "questions");
        this.a = l;
        this.b = str;
        this.c = results;
        this.d = questions;
        this.e = i;
        this.f = i2;
        this.g = studiableMeteringData;
        this.h = results.a;
        this.i = results.c;
        ArrayList arrayList = new ArrayList(C.q(questions, 10));
        Iterator it2 = questions.iterator();
        int i3 = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i4 = i3 + 1;
            if (i3 < 0) {
                B.p();
                throw null;
            }
            StudiableQuestion question = (StudiableQuestion) next;
            StudiableQuestionGradedAnswer gradedAnswer = (StudiableQuestionGradedAnswer) this.c.b.get(i3);
            Intrinsics.checkNotNullParameter(question, "question");
            Intrinsics.checkNotNullParameter(gradedAnswer, "gradedAnswer");
            boolean z = gradedAnswer.a;
            StudiableQuestionFeedback studiableQuestionFeedback = gradedAnswer.b;
            StudiableQuestionResponse studiableQuestionResponse = studiableQuestionFeedback.a;
            if (studiableQuestionResponse instanceof WrittenResponse) {
                fVar = new f(z, new StudiableText(((WrittenResponse) studiableQuestionResponse).a, null, null), 60);
            } else if (studiableQuestionResponse instanceof TrueFalseResponse) {
                fVar = new f(z, new StudiableText(String.valueOf(((TrueFalseResponse) studiableQuestionResponse).a), null, null), 60);
            } else if (studiableQuestionResponse instanceof MultipleChoiceResponse) {
                fVar = k7.b((QuestionSectionData) ((MultipleChoiceStudiableQuestion) question).c.get(((MultipleChoiceResponse) studiableQuestionResponse).a), z);
            } else {
                if (studiableQuestionResponse != null) {
                    throw new IllegalArgumentException("Not a valid test submitted response: [" + studiableQuestionResponse + "]");
                }
                timber.log.c.a.e(new IllegalArgumentException("Not a valid test submitted response: null"));
                fVar = new f(z, null, 62);
            }
            arrayList.add(new g(question, fVar, studiableQuestionResponse, k7.b(studiableQuestionFeedback.c, true), studiableQuestionFeedback.b));
            i3 = i4;
        }
        this.j = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a.equals(hVar.a) && Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c) && Intrinsics.b(this.d, hVar.d) && this.e == hVar.e && this.f == hVar.f && this.g.equals(hVar.g);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return this.g.hashCode() + d0.b(this.f, d0.b(this.e, d0.h(this.d, (this.c.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31)) * 31, 31), 31), 31);
    }

    public final String toString() {
        return "TestResultsData(setId=" + this.a + ", studySessionId=" + this.b + ", results=" + this.c + ", questions=" + this.d + ", questionCount=" + this.e + ", correctCount=" + this.f + ", learnMeteringData=" + this.g + ")";
    }
}
