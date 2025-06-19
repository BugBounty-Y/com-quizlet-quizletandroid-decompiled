package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* renamed from: androidx.compose.material3.z1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0768z1 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;

    public C0768z1(long j, long j2, long j3, long j4) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C0768z1)) {
            return false;
        }
        C0768z1 c0768z1 = (C0768z1) obj;
        return C0861v.c(this.a, c0768z1.a) && C0861v.c(this.b, c0768z1.b) && C0861v.c(this.c, c0768z1.c) && C0861v.c(this.d, c0768z1.d);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }
}
