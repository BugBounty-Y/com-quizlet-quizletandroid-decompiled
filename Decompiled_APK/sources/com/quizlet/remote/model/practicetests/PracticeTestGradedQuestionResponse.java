package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestGradedQuestionResponse {
    public final String a;
    public final String b;
    public final List c;
    public final Map d;
    public final String e;
    public final int f;
    public final List g;
    public final int h;
    public final List i;
    public final boolean j;
    public final boolean k;
    public final String l;
    public final String m;

    public PracticeTestGradedQuestionResponse(String questionUuid, String question, List answer, Map map, String questionFormat, int i, List userAnswer, int i2, List list, boolean z, boolean z2, String contentFormat, String str) {
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(contentFormat, "contentFormat");
        this.a = questionUuid;
        this.b = question;
        this.c = answer;
        this.d = map;
        this.e = questionFormat;
        this.f = i;
        this.g = userAnswer;
        this.h = i2;
        this.i = list;
        this.j = z;
        this.k = z2;
        this.l = contentFormat;
        this.m = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestGradedQuestionResponse)) {
            return false;
        }
        PracticeTestGradedQuestionResponse practiceTestGradedQuestionResponse = (PracticeTestGradedQuestionResponse) obj;
        return Intrinsics.b(this.a, practiceTestGradedQuestionResponse.a) && Intrinsics.b(this.b, practiceTestGradedQuestionResponse.b) && Intrinsics.b(this.c, practiceTestGradedQuestionResponse.c) && Intrinsics.b(this.d, practiceTestGradedQuestionResponse.d) && Intrinsics.b(this.e, practiceTestGradedQuestionResponse.e) && this.f == practiceTestGradedQuestionResponse.f && Intrinsics.b(this.g, practiceTestGradedQuestionResponse.g) && this.h == practiceTestGradedQuestionResponse.h && Intrinsics.b(this.i, practiceTestGradedQuestionResponse.i) && this.j == practiceTestGradedQuestionResponse.j && this.k == practiceTestGradedQuestionResponse.k && Intrinsics.b(this.l, practiceTestGradedQuestionResponse.l) && Intrinsics.b(this.m, practiceTestGradedQuestionResponse.m);
    }

    public final int hashCode() {
        int iF = d0.f(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        Map map = this.d;
        int iB = d0.b(this.h, d0.f(d0.b(this.f, d0.e((iF + (map == null ? 0 : map.hashCode())) * 31, 31, this.e), 31), 31, this.g), 31);
        List list = this.i;
        int iE = d0.e(d0.g(d0.g((iB + (list == null ? 0 : list.hashCode())) * 31, 31, this.j), 31, this.k), 31, this.l);
        String str = this.m;
        return iE + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestGradedQuestionResponse(questionUuid=");
        sb.append(this.a);
        sb.append(", question=");
        sb.append(this.b);
        sb.append(", answer=");
        sb.append(this.c);
        sb.append(", answerOptions=");
        sb.append(this.d);
        sb.append(", questionFormat=");
        sb.append(this.e);
        sb.append(", questionIndex=");
        sb.append(this.f);
        sb.append(", userAnswer=");
        sb.append(this.g);
        sb.append(", grade=");
        sb.append(this.h);
        sb.append(", images=");
        sb.append(this.i);
        sb.append(", active=");
        sb.append(this.j);
        sb.append(", excluded=");
        sb.append(this.k);
        sb.append(", contentFormat=");
        sb.append(this.l);
        sb.append(", mediaType=");
        return android.support.v4.media.session.a.t(sb, this.m, ")");
    }

    public /* synthetic */ PracticeTestGradedQuestionResponse(String str, String str2, List list, Map map, String str3, int i, List list2, int i2, List list3, boolean z, boolean z2, String str4, String str5, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, list, (i3 & 8) != 0 ? null : map, str3, i, list2, i2, (i3 & 256) != 0 ? null : list3, z, z2, str4, (i3 & 4096) != 0 ? null : str5);
    }
}
