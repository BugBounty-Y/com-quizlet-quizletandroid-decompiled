package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class Z0 extends W0 {
    public final int b;
    public final int c;
    public final int d;
    public final int[] e;
    public final int[] f;

    public Z0(int i, int i2, int i3, int[] iArr, int[] iArr2) {
        super("MLLT");
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = iArr;
        this.f = iArr2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && Z0.class == obj.getClass()) {
            Z0 z0 = (Z0) obj;
            if (this.b == z0.b && this.c == z0.c && this.d == z0.d && Arrays.equals(this.e, z0.e) && Arrays.equals(this.f, z0.f)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.f) + ((Arrays.hashCode(this.e) + ((((((this.b + 527) * 31) + this.c) * 31) + this.d) * 31)) * 31);
    }
}
