package com.quizlet.features.practicetest.takingtest.data;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4412f {
    public final String a;
    public final String b;
    public final List c;
    public final InterfaceC4410d d;
    public final List e;
    public final EnumC4533y0 f;
    public final int g;
    public final boolean h;
    public final boolean i;

    public C4412f(String questionId, String question, List answer, InterfaceC4410d answerOptions, List list, EnumC4533y0 questionFormat, int i, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(answerOptions, "answerOptions");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        this.a = questionId;
        this.b = question;
        this.c = answer;
        this.d = answerOptions;
        this.e = list;
        this.f = questionFormat;
        this.g = i;
        this.h = z;
        this.i = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4412f)) {
            return false;
        }
        C4412f c4412f = (C4412f) obj;
        return Intrinsics.b(this.a, c4412f.a) && Intrinsics.b(this.b, c4412f.b) && Intrinsics.b(this.c, c4412f.c) && Intrinsics.b(this.d, c4412f.d) && Intrinsics.b(this.e, c4412f.e) && this.f == c4412f.f && this.g == c4412f.g && this.h == c4412f.h && this.i == c4412f.i;
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + d0.f(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31;
        List list = this.e;
        return Boolean.hashCode(this.i) + d0.g(d0.b(this.g, (this.f.hashCode() + ((iHashCode + (list == null ? 0 : list.hashCode())) * 31)) * 31, 31), 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestQuestionData(questionId=");
        sb.append(this.a);
        sb.append(", question=");
        sb.append(this.b);
        sb.append(", answer=");
        sb.append(this.c);
        sb.append(", answerOptions=");
        sb.append(this.d);
        sb.append(", images=");
        sb.append(this.e);
        sb.append(", questionFormat=");
        sb.append(this.f);
        sb.append(", positionIndex=");
        sb.append(this.g);
        sb.append(", isActive=");
        sb.append(this.h);
        sb.append(", hasBeenRemoved=");
        return android.support.v4.media.session.a.o(")", sb, this.i);
    }
}
