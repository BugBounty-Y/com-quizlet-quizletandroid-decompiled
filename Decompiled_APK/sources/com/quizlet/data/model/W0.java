package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class W0 {
    public final String a;
    public final String b;
    public final long c;
    public final int d;
    public final int e;

    public W0(String practiceTestId, String startedAt, long j, int i, int i2) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(startedAt, "startedAt");
        this.a = practiceTestId;
        this.b = startedAt;
        this.c = j;
        this.d = i;
        this.e = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof W0)) {
            return false;
        }
        W0 w0 = (W0) obj;
        return Intrinsics.b(this.a, w0.a) && Intrinsics.b(this.b, w0.b) && this.c == w0.c && this.d == w0.d && this.e == w0.e;
    }

    public final int hashCode() {
        return Integer.hashCode(this.e) + androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestPastResult(practiceTestId=");
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
