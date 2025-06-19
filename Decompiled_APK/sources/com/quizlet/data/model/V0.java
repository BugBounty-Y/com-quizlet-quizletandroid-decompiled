package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class V0 {
    public final String a;
    public final String b;
    public final long c;
    public final int d;
    public final int e;
    public final int f;

    public V0(String practiceTestId, String startedAt, long j, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(startedAt, "startedAt");
        this.a = practiceTestId;
        this.b = startedAt;
        this.c = j;
        this.d = i;
        this.e = i2;
        this.f = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof V0)) {
            return false;
        }
        V0 v0 = (V0) obj;
        return Intrinsics.b(this.a, v0.a) && Intrinsics.b(this.b, v0.b) && this.c == v0.c && this.d == v0.d && this.e == v0.e && this.f == v0.f;
    }

    public final int hashCode() {
        return Integer.hashCode(this.f) + androidx.compose.animation.d0.b(this.e, androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestPastExam(practiceTestId=");
        sb.append(this.a);
        sb.append(", startedAt=");
        sb.append(this.b);
        sb.append(", durationSeconds=");
        sb.append(this.c);
        sb.append(", scorePercentage=");
        sb.append(this.d);
        sb.append(", correctCount=");
        sb.append(this.e);
        sb.append(", totalCount=");
        return android.support.v4.media.session.a.r(sb, this.f, ")");
    }
}
