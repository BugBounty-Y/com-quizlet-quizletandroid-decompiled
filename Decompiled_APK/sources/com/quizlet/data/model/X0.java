package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class X0 {
    public final String a;
    public final String b;
    public final List c;
    public final List d;
    public final EnumC4533y0 e;
    public final ArrayList f;

    public X0(String questionId, String question, List answer, List answerOptions, EnumC4533y0 questionFormat, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(answerOptions, "answerOptions");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        this.a = questionId;
        this.b = question;
        this.c = answer;
        this.d = answerOptions;
        this.e = questionFormat;
        this.f = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof X0)) {
            return false;
        }
        X0 x0 = (X0) obj;
        return Intrinsics.b(this.a, x0.a) && Intrinsics.b(this.b, x0.b) && Intrinsics.b(this.c, x0.c) && Intrinsics.b(this.d, x0.d) && this.e == x0.e && Intrinsics.b(this.f, x0.f);
    }

    public final int hashCode() {
        int iHashCode = (this.e.hashCode() + androidx.compose.animation.d0.f(androidx.compose.animation.d0.f(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31;
        ArrayList arrayList = this.f;
        return iHashCode + (arrayList == null ? 0 : arrayList.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestQuestion(questionId=");
        sb.append(this.a);
        sb.append(", question=");
        sb.append(this.b);
        sb.append(", answer=");
        sb.append(this.c);
        sb.append(", answerOptions=");
        sb.append(this.d);
        sb.append(", questionFormat=");
        sb.append(this.e);
        sb.append(", images=");
        return AbstractC0147y.f(")", sb, this.f);
    }
}
