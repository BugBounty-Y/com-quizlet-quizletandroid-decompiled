package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* renamed from: androidx.compose.material3.k3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0672k3 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;

    public C0672k3(long j, long j2, long j3, long j4) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C0672k3)) {
            return false;
        }
        C0672k3 c0672k3 = (C0672k3) obj;
        return C0861v.c(this.a, c0672k3.a) && C0861v.c(this.b, c0672k3.b) && C0861v.c(this.c, c0672k3.c) && C0861v.c(this.d, c0672k3.d);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }
}
