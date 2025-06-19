package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestsAnswerOptionResponse {
    public final String a;
    public final List b;

    public PracticeTestsAnswerOptionResponse(String option, List list) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestsAnswerOptionResponse)) {
            return false;
        }
        PracticeTestsAnswerOptionResponse practiceTestsAnswerOptionResponse = (PracticeTestsAnswerOptionResponse) obj;
        return Intrinsics.b(this.a, practiceTestsAnswerOptionResponse.a) && Intrinsics.b(this.b, practiceTestsAnswerOptionResponse.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        List list = this.b;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        return "PracticeTestsAnswerOptionResponse(option=" + this.a + ", images=" + this.b + ")";
    }

    public /* synthetic */ PracticeTestsAnswerOptionResponse(String str, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i & 2) != 0 ? null : list);
    }
}
