package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class OD {
    public static final OD c;
    public final long a;
    public final long b;

    static {
        OD od = new OD(0L, 0L);
        new OD(Long.MAX_VALUE, Long.MAX_VALUE);
        new OD(Long.MAX_VALUE, 0L);
        new OD(0L, Long.MAX_VALUE);
        c = od;
    }

    public OD(long j, long j2) {
        AbstractC1795We.B(j >= 0);
        AbstractC1795We.B(j2 >= 0);
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && OD.class == obj.getClass()) {
            OD od = (OD) obj;
            if (this.a == od.a && this.b == od.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (((int) this.a) * 31) + ((int) this.b);
    }
}
