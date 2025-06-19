package com.quizlet.features.practicetest.common.data;

import com.quizlet.generated.enums.EnumC4507o0;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.collections.M;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l {
    public final Set a;
    public final Set b;
    public final Set c;

    public l() {
        EnumC4533y0[] elements = {EnumC4533y0.MCQ_WITH_SINGLE_ANSWER, EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE};
        Intrinsics.checkNotNullParameter(elements, "elements");
        Set questionFormats = C4933y.T(elements);
        Set contentFormats = Z.b(EnumC4507o0.PLAINTEXT);
        M mediaTypes = M.a;
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(contentFormats, "contentFormats");
        Intrinsics.checkNotNullParameter(mediaTypes, "mediaTypes");
        this.a = questionFormats;
        this.b = contentFormats;
        this.c = mediaTypes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && Intrinsics.b(this.b, lVar.b) && Intrinsics.b(this.c, lVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SupportedQuestionTypes(questionFormats=" + this.a + ", contentFormats=" + this.b + ", mediaTypes=" + this.c + ")";
    }
}
