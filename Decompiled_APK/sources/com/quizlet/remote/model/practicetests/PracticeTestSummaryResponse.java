package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestSummaryResponse {
    public final String a;
    public final String b;
    public final long c;
    public final int d;
    public final int e;

    public PracticeTestSummaryResponse(String practiceTestUuid, String startedAt, long j, int i, int i2) {
        Intrinsics.checkNotNullParameter(practiceTestUuid, "practiceTestUuid");
        Intrinsics.checkNotNullParameter(startedAt, "startedAt");
        this.a = practiceTestUuid;
        this.b = startedAt;
        this.c = j;
        this.d = i;
        this.e = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestSummaryResponse)) {
            return false;
        }
        PracticeTestSummaryResponse practiceTestSummaryResponse = (PracticeTestSummaryResponse) obj;
        return Intrinsics.b(this.a, practiceTestSummaryResponse.a) && Intrinsics.b(this.b, practiceTestSummaryResponse.b) && this.c == practiceTestSummaryResponse.c && this.d == practiceTestSummaryResponse.d && this.e == practiceTestSummaryResponse.e;
    }

    public final int hashCode() {
        return Integer.hashCode(this.e) + d0.b(this.d, d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestSummaryResponse(practiceTestUuid=");
        sb.append(this.a);
        sb.append(", startedAt=");
        sb.append(this.b);
        sb.append(", durationSeconds=");
        sb.append(this.c);
        sb.append(", correctCount=");
        sb.append(this.d);
        sb.append(", totalCount=");
        return android.support.v4.media.session.a.r(sb, this.e, ")");
    }
}
