package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class S0 extends W0 {
    public final String b;
    public final boolean c;
    public final boolean d;
    public final String[] e;
    public final W0[] f;

    public S0(String str, boolean z, boolean z2, String[] strArr, W0[] w0Arr) {
        super("CTOC");
        this.b = str;
        this.c = z;
        this.d = z2;
        this.e = strArr;
        this.f = w0Arr;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && S0.class == obj.getClass()) {
            S0 s0 = (S0) obj;
            if (this.c == s0.c && this.d == s0.d && Objects.equals(this.b, s0.b) && Arrays.equals(this.e, s0.e) && Arrays.equals(this.f, s0.f)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode() + (((((this.c ? 1 : 0) + 527) * 31) + (this.d ? 1 : 0)) * 31);
    }
}
