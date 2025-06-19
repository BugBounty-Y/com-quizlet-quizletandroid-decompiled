package com.google.android.gms.internal.ads;

import android.os.Build;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.dE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1961dE {
    public static final C1961dE d;
    public final int a;
    public final int b;
    public final AbstractC2459ou c;

    static {
        C1961dE c1961dE;
        if (Build.VERSION.SDK_INT >= 33) {
            C2416nu c2416nu = new C2416nu(4);
            for (int i = 1; i <= 10; i++) {
                c2416nu.j(Integer.valueOf(Yo.n(i)));
            }
            c1961dE = new C1961dE(2, c2416nu.l());
        } else {
            c1961dE = new C1961dE(2, 10);
        }
        d = c1961dE;
    }

    public C1961dE(int i, int i2) {
        this.a = i;
        this.b = i2;
        this.c = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1961dE)) {
            return false;
        }
        C1961dE c1961dE = (C1961dE) obj;
        return this.a == c1961dE.a && this.b == c1961dE.b && Objects.equals(this.c, c1961dE.c);
    }

    public final int hashCode() {
        AbstractC2459ou abstractC2459ou = this.c;
        return (((this.a * 31) + this.b) * 31) + (abstractC2459ou == null ? 0 : abstractC2459ou.hashCode());
    }

    public final String toString() {
        return "AudioProfile[format=" + this.a + ", maxChannelCount=" + this.b + ", channelMasks=" + String.valueOf(this.c) + "]";
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C1961dE(int r2, java.util.Set r3) {
        /*
            r1 = this;
            r1.<init>()
            r1.a = r2
            java.util.Set r3 = (java.util.Set) r3
            int r2 = com.google.android.gms.internal.ads.AbstractC2459ou.c
            boolean r2 = r3 instanceof com.google.android.gms.internal.ads.AbstractC2459ou
            if (r2 == 0) goto L1b
            boolean r2 = r3 instanceof java.util.SortedSet
            if (r2 != 0) goto L1b
            r2 = r3
            com.google.android.gms.internal.ads.ou r2 = (com.google.android.gms.internal.ads.AbstractC2459ou) r2
            boolean r0 = r2.h()
            if (r0 != 0) goto L1b
            goto L24
        L1b:
            java.lang.Object[] r2 = r3.toArray()
            int r3 = r2.length
            com.google.android.gms.internal.ads.ou r2 = com.google.android.gms.internal.ads.AbstractC2459ou.o(r3, r2)
        L24:
            r1.c = r2
            com.google.android.gms.internal.ads.Pu r2 = r2.g()
            r3 = 0
        L2b:
            boolean r0 = r2.hasNext()
            if (r0 == 0) goto L44
            java.lang.Object r0 = r2.next()
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r0 = r0.intValue()
            int r0 = java.lang.Integer.bitCount(r0)
            int r3 = java.lang.Math.max(r3, r0)
            goto L2b
        L44:
            r1.b = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1961dE.<init>(int, java.util.Set):void");
    }
}
