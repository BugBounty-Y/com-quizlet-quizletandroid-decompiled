package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.f1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4127f1 {
    public final long a;
    public final long b;
    public final com.quizlet.generated.enums.G1 c;
    public final Long d;

    public C4127f1(long j, long j2, com.quizlet.generated.enums.G1 containerType, Long l) {
        Intrinsics.checkNotNullParameter(containerType, "containerType");
        this.a = j;
        this.b = j2;
        this.c = containerType;
        this.d = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4127f1)) {
            return false;
        }
        C4127f1 c4127f1 = (C4127f1) obj;
        return this.a == c4127f1.a && this.b == c4127f1.b && this.c == c4127f1.c && Intrinsics.b(this.d, c4127f1.d);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b)) * 31;
        Long l = this.d;
        return iHashCode + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "ProgressReset(personId=" + this.a + ", containerId=" + this.b + ", containerType=" + this.c + ", resetTimeSec=" + this.d + ")";
    }
}
