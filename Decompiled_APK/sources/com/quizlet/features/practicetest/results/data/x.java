package com.quizlet.features.practicetest.results.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x {
    public final String a;
    public final String b;
    public final boolean c;
    public final d d;
    public final String e;
    public final String f;

    public x(String questionId, String question, boolean z, d answer, String str, String str2) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = questionId;
        this.b = question;
        this.c = z;
        this.d = answer;
        this.e = str;
        this.f = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return Intrinsics.b(this.a, xVar.a) && Intrinsics.b(this.b, xVar.b) && this.c == xVar.c && Intrinsics.b(this.d, xVar.d) && Intrinsics.b(this.e, xVar.e) && Intrinsics.b(this.f, xVar.f);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31;
        String str = this.e;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionResult(questionId=");
        sb.append(this.a);
        sb.append(", question=");
        sb.append(this.b);
        sb.append(", isExcluded=");
        sb.append(this.c);
        sb.append(", answer=");
        sb.append(this.d);
        sb.append(", imageUrl=");
        sb.append(this.e);
        sb.append(", imageCaption=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }
}
