package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestResult {
    public final List a;
    public final int b;
    public final int c;
    public final String d;
    public final PracticeTestConfigurationResponse e;
    public final RemotePracticeTestSetId f;
    public final Map g;

    public PracticeTestResult(List gradedQuestions, int i, int i2, String questionBankUuid, PracticeTestConfigurationResponse configuration, RemotePracticeTestSetId practiceTestMetadata, Map questionCounts) {
        Intrinsics.checkNotNullParameter(gradedQuestions, "gradedQuestions");
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(practiceTestMetadata, "practiceTestMetadata");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        this.a = gradedQuestions;
        this.b = i;
        this.c = i2;
        this.d = questionBankUuid;
        this.e = configuration;
        this.f = practiceTestMetadata;
        this.g = questionCounts;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestResult)) {
            return false;
        }
        PracticeTestResult practiceTestResult = (PracticeTestResult) obj;
        return Intrinsics.b(this.a, practiceTestResult.a) && this.b == practiceTestResult.b && this.c == practiceTestResult.c && Intrinsics.b(this.d, practiceTestResult.d) && Intrinsics.b(this.e, practiceTestResult.e) && Intrinsics.b(this.f, practiceTestResult.f) && Intrinsics.b(this.g, practiceTestResult.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + d0.e(d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31, this.d)) * 31)) * 31);
    }

    public final String toString() {
        return "PracticeTestResult(gradedQuestions=" + this.a + ", durationSeconds=" + this.b + ", round=" + this.c + ", questionBankUuid=" + this.d + ", configuration=" + this.e + ", practiceTestMetadata=" + this.f + ", questionCounts=" + this.g + ")";
    }
}
