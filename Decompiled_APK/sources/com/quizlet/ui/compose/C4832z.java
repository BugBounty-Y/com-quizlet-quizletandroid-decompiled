package com.quizlet.ui.compose;

import androidx.compose.ui.graphics.C0861v;

/* renamed from: com.quizlet.ui.compose.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4832z {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final long h;
    public final long i;

    public C4832z(long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8, long j9) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
        this.g = j7;
        this.h = j8;
        this.i = j9;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C4832z)) {
            return false;
        }
        C4832z c4832z = (C4832z) obj;
        return C0861v.c(this.a, c4832z.a) && C0861v.c(this.b, c4832z.b) && C0861v.c(this.c, c4832z.c) && C0861v.c(this.d, c4832z.d) && C0861v.c(this.e, c4832z.e) && C0861v.c(this.f, c4832z.f) && C0861v.c(this.g, c4832z.g) && C0861v.c(this.h, c4832z.h) && C0861v.c(this.i, c4832z.i);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.i) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
    }
}
