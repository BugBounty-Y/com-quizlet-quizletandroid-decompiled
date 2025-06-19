package com.quizlet.ui.compose;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes3.dex */
public final class S {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;

    public S(long j, long j2, long j3, long j4, long j5, long j6) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof S)) {
            return false;
        }
        S s = (S) obj;
        return C0861v.c(this.a, s.a) && C0861v.c(this.b, s.b) && C0861v.c(this.c, s.c) && C0861v.c(this.d, s.d) && C0861v.c(this.e, s.e) && C0861v.c(this.f, s.f);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.f) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }
}
