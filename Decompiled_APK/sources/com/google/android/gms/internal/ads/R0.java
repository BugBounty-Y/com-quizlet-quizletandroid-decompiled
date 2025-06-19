package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class R0 extends W0 {
    public final String b;
    public final int c;
    public final int d;
    public final long e;
    public final long f;
    public final W0[] g;

    public R0(String str, int i, int i2, long j, long j2, W0[] w0Arr) {
        super("CHAP");
        this.b = str;
        this.c = i;
        this.d = i2;
        this.e = j;
        this.f = j2;
        this.g = w0Arr;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && R0.class == obj.getClass()) {
            R0 r0 = (R0) obj;
            if (this.c == r0.c && this.d == r0.d && this.e == r0.e && this.f == r0.f && Objects.equals(this.b, r0.b) && Arrays.equals(this.g, r0.g)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode() + ((((((((this.c + 527) * 31) + this.d) * 31) + ((int) this.e)) * 31) + ((int) this.f)) * 31);
    }
}
