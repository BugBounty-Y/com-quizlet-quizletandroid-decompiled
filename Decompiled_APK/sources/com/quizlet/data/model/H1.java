package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class H1 {
    public final long a;
    public final long b;
    public final long c;
    public final com.quizlet.generated.enums.G1 d;
    public final com.quizlet.generated.enums.A1 e;
    public final long f;
    public final long g;
    public final long h;
    public final boolean i;
    public final boolean j;
    public final long k;

    public H1(long j, long j2, long j3, com.quizlet.generated.enums.G1 itemType, com.quizlet.generated.enums.A1 modeType, long j4, long j5, long j6, boolean z, boolean z2, long j7) {
        Intrinsics.checkNotNullParameter(itemType, "itemType");
        Intrinsics.checkNotNullParameter(modeType, "modeType");
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = itemType;
        this.e = modeType;
        this.f = j4;
        this.g = j5;
        this.h = j6;
        this.i = z;
        this.j = z2;
        this.k = j7;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H1)) {
            return false;
        }
        H1 h1 = (H1) obj;
        return this.a == h1.a && this.b == h1.b && this.c == h1.c && this.d == h1.d && this.e == h1.e && this.f == h1.f && this.g == h1.g && this.h == h1.h && this.i == h1.i && this.j == h1.j && this.k == h1.k;
    }

    public final int hashCode() {
        return Long.hashCode(this.k) + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((this.e.hashCode() + ((this.d.hashCode() + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c)) * 31)) * 31, 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Session(id=");
        sb.append(this.a);
        sb.append(", personId=");
        sb.append(this.b);
        sb.append(", itemId=");
        sb.append(this.c);
        sb.append(", itemType=");
        sb.append(this.d);
        sb.append(", modeType=");
        sb.append(this.e);
        sb.append(", timestamp=");
        sb.append(this.f);
        sb.append(", endedTimestamp=");
        sb.append(this.g);
        sb.append(", score=");
        sb.append(this.h);
        sb.append(", selectedTermsOnly=");
        sb.append(this.i);
        sb.append(", hidden=");
        sb.append(this.j);
        sb.append(", lastModified=");
        return android.support.v4.media.session.a.g(this.k, ")", sb);
    }
}
