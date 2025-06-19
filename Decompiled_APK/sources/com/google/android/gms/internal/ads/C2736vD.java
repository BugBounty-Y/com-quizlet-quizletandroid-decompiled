package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.vD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2736vD {
    public final C2093gF a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final boolean f;
    public final boolean g;
    public final boolean h;

    public C2736vD(C2093gF c2093gF, long j, long j2, long j3, long j4, boolean z, boolean z2, boolean z3) {
        AbstractC1795We.B(!z3 || z);
        AbstractC1795We.B(!z2 || z);
        this.a = c2093gF;
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = j4;
        this.f = z;
        this.g = z2;
        this.h = z3;
    }

    public final C2736vD a(long j) {
        if (j == this.c) {
            return this;
        }
        return new C2736vD(this.a, this.b, j, this.d, this.e, this.f, this.g, this.h);
    }

    public final C2736vD b(long j) {
        if (j == this.b) {
            return this;
        }
        return new C2736vD(this.a, j, this.c, this.d, this.e, this.f, this.g, this.h);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2736vD.class == obj.getClass()) {
            C2736vD c2736vD = (C2736vD) obj;
            if (this.b == c2736vD.b && this.c == c2736vD.c && this.d == c2736vD.d && this.e == c2736vD.e && this.f == c2736vD.f && this.g == c2736vD.g && this.h == c2736vD.h && Objects.equals(this.a, c2736vD.a)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((((((((((((this.a.hashCode() + 527) * 31) + ((int) this.b)) * 31) + ((int) this.c)) * 31) + ((int) this.d)) * 31) + ((int) this.e)) * 29791) + (this.f ? 1 : 0)) * 31) + (this.g ? 1 : 0)) * 31) + (this.h ? 1 : 0);
    }
}
