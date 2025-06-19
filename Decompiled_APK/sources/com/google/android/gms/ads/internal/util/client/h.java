package com.google.android.gms.ads.internal.util.client;

/* loaded from: classes2.dex */
public final class h {
    public final int a;
    public final int b;
    public final double c;
    public final boolean d;

    public h(int i, int i2, double d, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = d;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof h) {
            h hVar = (h) obj;
            if (this.a == hVar.a && this.b == hVar.b && Double.doubleToLongBits(this.c) == Double.doubleToLongBits(hVar.c) && this.d == hVar.d) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        double d = this.c;
        return ((((int) (Double.doubleToLongBits(d) ^ (Double.doubleToLongBits(d) >>> 32))) ^ ((((this.a ^ 1000003) * 1000003) ^ this.b) * 1000003)) * 1000003) ^ (true != this.d ? 1237 : 1231);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PingStrategy{maxAttempts=");
        sb.append(this.a);
        sb.append(", initialBackoffMs=");
        sb.append(this.b);
        sb.append(", backoffMultiplier=");
        sb.append(this.c);
        sb.append(", bufferAfterMaxAttempts=");
        return android.support.v4.media.session.a.o("}", sb, this.d);
    }
}
