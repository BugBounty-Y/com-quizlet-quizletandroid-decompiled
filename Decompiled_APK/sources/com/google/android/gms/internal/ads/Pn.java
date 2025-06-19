package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Pn {
    public static final Pn c = new Pn(-1, -1);
    public final int a;
    public final int b;

    static {
        new Pn(0, 0);
    }

    public Pn(int i, int i2) {
        boolean z = false;
        if ((i == -1 || i >= 0) && (i2 == -1 || i2 >= 0)) {
            z = true;
        }
        AbstractC1795We.B(z);
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (obj instanceof Pn) {
            Pn pn = (Pn) obj;
            if (this.a == pn.a && this.b == pn.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.a;
        return ((i >>> 16) | (i << 16)) ^ this.b;
    }

    public final String toString() {
        return this.a + "x" + this.b;
    }
}
