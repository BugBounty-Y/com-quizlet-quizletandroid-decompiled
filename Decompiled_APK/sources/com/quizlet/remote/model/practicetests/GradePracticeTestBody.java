package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class GradePracticeTestBody {
    public final String a;
    public final String b;
    public final List c;
    public final String d;
    public final String e;
    public final long f;
    public final PracticeTestMetadata g;

    public GradePracticeTestBody(String questionBankUuid, String practiceTestSessionId, List ungradedQuestions, String testStartedAt, String testSubmittedAt, long j, PracticeTestMetadata practiceTestMetadata) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        Intrinsics.checkNotNullParameter(ungradedQuestions, "ungradedQuestions");
        Intrinsics.checkNotNullParameter(testStartedAt, "testStartedAt");
        Intrinsics.checkNotNullParameter(testSubmittedAt, "testSubmittedAt");
        Intrinsics.checkNotNullParameter(practiceTestMetadata, "practiceTestMetadata");
        this.a = questionBankUuid;
        this.b = practiceTestSessionId;
        this.c = ungradedQuestions;
        this.d = testStartedAt;
        this.e = testSubmittedAt;
        this.f = j;
        this.g = practiceTestMetadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GradePracticeTestBody)) {
            return false;
        }
        GradePracticeTestBody gradePracticeTestBody = (GradePracticeTestBody) obj;
        return Intrinsics.b(this.a, gradePracticeTestBody.a) && Intrinsics.b(this.b, gradePracticeTestBody.b) && Intrinsics.b(this.c, gradePracticeTestBody.c) && Intrinsics.b(this.d, gradePracticeTestBody.d) && Intrinsics.b(this.e, gradePracticeTestBody.e) && this.f == gradePracticeTestBody.f && Intrinsics.b(this.g, gradePracticeTestBody.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + d0.d(d0.e(d0.e(d0.f(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f);
    }

    public final String toString() {
        return "GradePracticeTestBody(questionBankUuid=" + this.a + ", practiceTestSessionId=" + this.b + ", ungradedQuestions=" + this.c + ", testStartedAt=" + this.d + ", testSubmittedAt=" + this.e + ", testCompletionTimeSeconds=" + this.f + ", practiceTestMetadata=" + this.g + ")";
    }
}
