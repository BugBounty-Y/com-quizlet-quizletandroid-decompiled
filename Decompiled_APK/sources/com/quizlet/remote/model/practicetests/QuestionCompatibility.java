package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4507o0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionCompatibility {
    public final List a;
    public final List b;
    public final List c;

    public QuestionCompatibility(List questionFormats, List contentFormats, List list) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(contentFormats, "contentFormats");
        this.a = questionFormats;
        this.b = contentFormats;
        this.c = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionCompatibility)) {
            return false;
        }
        QuestionCompatibility questionCompatibility = (QuestionCompatibility) obj;
        return Intrinsics.b(this.a, questionCompatibility.a) && Intrinsics.b(this.b, questionCompatibility.b) && Intrinsics.b(this.c, questionCompatibility.c);
    }

    public final int hashCode() {
        int iF = d0.f(this.a.hashCode() * 31, 31, this.b);
        List list = this.c;
        return iF + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionCompatibility(questionFormats=");
        sb.append(this.a);
        sb.append(", contentFormats=");
        sb.append(this.b);
        sb.append(", mediaTypes=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public /* synthetic */ QuestionCompatibility(List list, List list2, List list3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? B.j(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER.a(), EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE.a()) : list, (i & 2) != 0 ? A.b(EnumC4507o0.PLAINTEXT.a()) : list2, (i & 4) != 0 ? null : list3);
    }
}
