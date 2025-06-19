package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class RD {
    public final long a;
    public final A9 b;
    public final int c;
    public final C2093gF d;
    public final long e;
    public final A9 f;
    public final int g;
    public final C2093gF h;
    public final long i;
    public final long j;

    public RD(long j, A9 a9, int i, C2093gF c2093gF, long j2, A9 a92, int i2, C2093gF c2093gF2, long j3, long j4) {
        this.a = j;
        this.b = a9;
        this.c = i;
        this.d = c2093gF;
        this.e = j2;
        this.f = a92;
        this.g = i2;
        this.h = c2093gF2;
        this.i = j3;
        this.j = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && RD.class == obj.getClass()) {
            RD rd = (RD) obj;
            if (this.a == rd.a && this.c == rd.c && this.e == rd.e && this.g == rd.g && this.i == rd.i && this.j == rd.j && Objects.equals(this.b, rd.b) && Objects.equals(this.d, rd.d) && Objects.equals(this.f, rd.f) && Objects.equals(this.h, rd.h)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Objects.hash(Long.valueOf(this.a), this.b, Integer.valueOf(this.c), this.d, Long.valueOf(this.e), this.f, Integer.valueOf(this.g), this.h, Long.valueOf(this.i), Long.valueOf(this.j));
    }
}
