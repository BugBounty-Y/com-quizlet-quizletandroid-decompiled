package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4533y0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.a1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4108a1 {
    public final String a;
    public final int b;
    public final EnumC4533y0 c;
    public final List d;
    public final List e;
    public final boolean f;

    public C4108a1(String questionUuid, int i, EnumC4533y0 questionFormat, List answer, List list, boolean z) {
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
        if (!(obj instanceof C4108a1)) {
            return false;
        }
        C4108a1 c4108a1 = (C4108a1) obj;
        return Intrinsics.b(this.a, c4108a1.a) && this.b == c4108a1.b && this.c == c4108a1.c && Intrinsics.b(this.d, c4108a1.d) && Intrinsics.b(this.e, c4108a1.e) && this.f == c4108a1.f;
    }

    public final int hashCode() {
        int iF = androidx.compose.animation.d0.f((this.c.hashCode() + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31)) * 31, 31, this.d);
        List list = this.e;
        return Boolean.hashCode(this.f) + ((iF + (list == null ? 0 : list.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestUngradedQuestion(questionUuid=");
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
