package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class Q0 extends W0 {
    public final byte[] b;

    public Q0(String str, byte[] bArr) {
        super(str);
        this.b = bArr;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && Q0.class == obj.getClass()) {
            Q0 q0 = (Q0) obj;
            if (this.a.equals(q0.a) && Arrays.equals(this.b, q0.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.b) + ((this.a.hashCode() + 527) * 31);
    }
}
