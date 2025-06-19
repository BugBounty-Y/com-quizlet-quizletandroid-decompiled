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
public final class PracticeTestsQuestionResponse {
    public final String a;
    public final String b;
    public final String c;
    public final List d;
    public final String e;
    public final Map f;
    public final String g;
    public final List h;
    public final List i;

    public PracticeTestsQuestionResponse(String questionId, String sourceId, String question, List answer, String source, Map map, String questionFormat, List list, List list2) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(sourceId, "sourceId");
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
        this.a = questionId;
        this.b = sourceId;
        this.c = question;
        this.d = answer;
        this.e = source;
        this.f = map;
        this.g = questionFormat;
        this.h = list;
        this.i = list2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestsQuestionResponse)) {
            return false;
        }
        PracticeTestsQuestionResponse practiceTestsQuestionResponse = (PracticeTestsQuestionResponse) obj;
        return Intrinsics.b(this.a, practiceTestsQuestionResponse.a) && Intrinsics.b(this.b, practiceTestsQuestionResponse.b) && Intrinsics.b(this.c, practiceTestsQuestionResponse.c) && Intrinsics.b(this.d, practiceTestsQuestionResponse.d) && Intrinsics.b(this.e, practiceTestsQuestionResponse.e) && Intrinsics.b(this.f, practiceTestsQuestionResponse.f) && Intrinsics.b(this.g, practiceTestsQuestionResponse.g) && Intrinsics.b(this.h, practiceTestsQuestionResponse.h) && Intrinsics.b(this.i, practiceTestsQuestionResponse.i);
    }

    public final int hashCode() {
        int iE = d0.e(d0.f(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
        Map map = this.f;
        int iE2 = d0.e((iE + (map == null ? 0 : map.hashCode())) * 31, 31, this.g);
        List list = this.h;
        int iHashCode = (iE2 + (list == null ? 0 : list.hashCode())) * 31;
        List list2 = this.i;
        return iHashCode + (list2 != null ? list2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestsQuestionResponse(questionId=");
        sb.append(this.a);
        sb.append(", sourceId=");
        sb.append(this.b);
        sb.append(", question=");
        sb.append(this.c);
        sb.append(", answer=");
        sb.append(this.d);
        sb.append(", source=");
        sb.append(this.e);
        sb.append(", answerOptions=");
        sb.append(this.f);
        sb.append(", questionFormat=");
        sb.append(this.g);
        sb.append(", concepts=");
        sb.append(this.h);
        sb.append(", images=");
        return android.support.v4.media.session.a.n(")", sb, this.i);
    }

    public /* synthetic */ PracticeTestsQuestionResponse(String str, String str2, String str3, List list, String str4, Map map, String str5, List list2, List list3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, str3, list, str4, (i & 32) != 0 ? null : map, str5, (i & 128) != 0 ? null : list2, (i & 256) != 0 ? null : list3);
    }
}
