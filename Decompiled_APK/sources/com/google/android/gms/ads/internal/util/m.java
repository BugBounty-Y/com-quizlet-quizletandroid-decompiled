package com.google.android.gms.ads.internal.util;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class m {
    public final String a;
    public final double b;
    public final double c;
    public final double d;
    public final int e;

    public m(String str, double d, double d2, double d3, int i) {
        this.a = str;
        this.c = d;
        this.b = d2;
        this.d = d3;
        this.e = i;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return com.google.android.gms.common.internal.u.l(this.a, mVar.a) && this.b == mVar.b && this.c == mVar.c && this.e == mVar.e && Double.compare(this.d, mVar.d) == 0;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, Double.valueOf(this.b), Double.valueOf(this.c), Double.valueOf(this.d), Integer.valueOf(this.e)});
    }

    public final String toString() {
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(this);
        uVar.b(this.a, "name");
        uVar.b(Double.valueOf(this.c), "minBound");
        uVar.b(Double.valueOf(this.b), "maxBound");
        uVar.b(Double.valueOf(this.d), "percent");
        uVar.b(Integer.valueOf(this.e), "count");
        return uVar.toString();
    }
}
