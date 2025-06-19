package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4501m0;
import com.quizlet.generated.enums.EnumC4507o0;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Q0 {
    public final String a;
    public final String b;
    public final List c;
    public final List d;
    public final Object e;
    public final EnumC4501m0 f;
    public final EnumC4533y0 g;
    public final int h;
    public final boolean i;
    public final boolean j;
    public final EnumC4507o0 k;
    public final ArrayList l;
    public final com.quizlet.generated.enums.A0 m;

    public Q0(String questionId, String testQuestion, List userAnswer, List answer, Map answerOptions, EnumC4501m0 grade, EnumC4533y0 questionFormat, int i, boolean z, boolean z2, EnumC4507o0 contentFormat, ArrayList arrayList, com.quizlet.generated.enums.A0 a0) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(testQuestion, "testQuestion");
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(answerOptions, "answerOptions");
        Intrinsics.checkNotNullParameter(grade, "grade");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        Intrinsics.checkNotNullParameter(contentFormat, "contentFormat");
        this.a = questionId;
        this.b = testQuestion;
        this.c = userAnswer;
        this.d = answer;
        this.e = answerOptions;
        this.f = grade;
        this.g = questionFormat;
        this.h = i;
        this.i = z;
        this.j = z2;
        this.k = contentFormat;
        this.l = arrayList;
        this.m = a0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Q0)) {
            return false;
        }
        Q0 q0 = (Q0) obj;
        return Intrinsics.b(this.a, q0.a) && Intrinsics.b(this.b, q0.b) && Intrinsics.b(this.c, q0.c) && Intrinsics.b(this.d, q0.d) && this.e.equals(q0.e) && this.f == q0.f && this.g == q0.g && this.h == q0.h && this.i == q0.i && this.j == q0.j && this.k == q0.k && this.l.equals(q0.l) && this.m == q0.m;
    }

    public final int hashCode() {
        int iH = androidx.compose.animation.d0.h(this.l, (this.k.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.h, (this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + androidx.compose.animation.d0.f(androidx.compose.animation.d0.f(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31)) * 31)) * 31, 31), 31, this.i), 31, this.j)) * 31, 31);
        com.quizlet.generated.enums.A0 a0 = this.m;
        return iH + (a0 == null ? 0 : a0.hashCode());
    }

    public final String toString() {
        return "PracticeTestGradedQuestion(questionId=" + this.a + ", testQuestion=" + this.b + ", userAnswer=" + this.c + ", answer=" + this.d + ", answerOptions=" + this.e + ", grade=" + this.f + ", questionFormat=" + this.g + ", questionIndex=" + this.h + ", active=" + this.i + ", excluded=" + this.j + ", contentFormat=" + this.k + ", images=" + this.l + ", mediaType=" + this.m + ")";
    }
}
