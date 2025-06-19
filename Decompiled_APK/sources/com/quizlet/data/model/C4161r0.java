package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.r0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4161r0 {
    public final Long a;
    public final long b;
    public final long c;
    public final int d;

    public C4161r0(long j, long j2, int i, Long l) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4161r0)) {
            return false;
        }
        C4161r0 c4161r0 = (C4161r0) obj;
        return Intrinsics.b(this.a, c4161r0.a) && this.b == c4161r0.b && this.c == c4161r0.c && this.d == c4161r0.d;
    }

    public final int hashCode() {
        Long l = this.a;
        return Integer.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IrrelevantRecommendation(id=");
        sb.append(this.a);
        sb.append(", personId=");
        sb.append(this.b);
        sb.append(", modelId=");
        sb.append(this.c);
        sb.append(", modelType=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
