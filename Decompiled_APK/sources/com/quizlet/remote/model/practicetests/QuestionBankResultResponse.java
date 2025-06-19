package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBankResultResponse {
    public final List a;

    public QuestionBankResultResponse(List practiceTestSummary) {
        Intrinsics.checkNotNullParameter(practiceTestSummary, "practiceTestSummary");
        this.a = practiceTestSummary;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QuestionBankResultResponse) && Intrinsics.b(this.a, ((QuestionBankResultResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("QuestionBankResultResponse(practiceTestSummary="), this.a);
    }

    public QuestionBankResultResponse(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
