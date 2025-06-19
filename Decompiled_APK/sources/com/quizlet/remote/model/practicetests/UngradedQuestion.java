package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.quizlet.remote.util.a
@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UngradedQuestion {
    public final String a;
    public final int b;
    public final String c;
    public final List d;
    public final List e;
    public final boolean f;

    public UngradedQuestion(String questionUuid, int i, String questionFormat, List answer, List list, boolean z) {
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = questionUuid;
        this.b = i;
        this.c = questionFormat;
        this.d = answer;
        this.e = list;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UngradedQuestion)) {
            return false;
        }
        UngradedQuestion ungradedQuestion = (UngradedQuestion) obj;
        return Intrinsics.b(this.a, ungradedQuestion.a) && this.b == ungradedQuestion.b && Intrinsics.b(this.c, ungradedQuestion.c) && Intrinsics.b(this.d, ungradedQuestion.d) && Intrinsics.b(this.e, ungradedQuestion.e) && this.f == ungradedQuestion.f;
    }

    public final int hashCode() {
        int iF = d0.f(d0.e(d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c), 31, this.d);
        List list = this.e;
        return Boolean.hashCode(this.f) + ((iF + (list == null ? 0 : list.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UngradedQuestion(questionUuid=");
        sb.append(this.a);
        sb.append(", questionIndex=");
        sb.append(this.b);
        sb.append(", questionFormat=");
        sb.append(this.c);
        sb.append(", answer=");
        sb.append(this.d);
        sb.append(", submittedAnswer=");
        sb.append(this.e);
        sb.append(", excluded=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
