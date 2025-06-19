package com.google.android.gms.internal.ads;

import android.net.NetworkCapabilities;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.n5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2385n5 extends AbstractCallableC2599s5 {
    public final S4 h;
    public final long i;
    public final long j;

    public C2385n5(Z4 z4, C1864b4 c1864b4, int i, S4 s4, long j, long j2) {
        super(z4, "Q2alXHIIp2vvtZN4ZNw4W3dXvS5FZxkSx8F3noC2XP6gq0/XB0ulYQV32h8ZSW0i", "bHzouddPHTqhUNsOeni/FRK++KVVMe5yU+yUqilZ/gg=", c1864b4, i, 11);
        this.h = s4;
        this.i = j;
        this.j = j2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        S4 s4 = this.h;
        if (s4 != null) {
            String str = (String) this.e.invoke(null, (NetworkCapabilities) s4.b, Long.valueOf(this.i), Long.valueOf(this.j));
            R4 r4 = new R4();
            HashMap mapC = AbstractC1972di.c(str);
            if (mapC != null) {
                r4.P = (Long) mapC.get(0);
                r4.Q = (Long) mapC.get(1);
                r4.R = (Long) mapC.get(2);
            }
            C1864b4 c1864b4 = this.d;
            synchronized (c1864b4) {
                try {
                    long jLongValue = r4.P.longValue();
                    c1864b4.e();
                    C2384n4.A((C2384n4) c1864b4.b, jLongValue);
                    if (((Long) r4.Q).longValue() >= 0) {
                        long jLongValue2 = ((Long) r4.Q).longValue();
                        c1864b4.e();
                        C2384n4.R((C2384n4) c1864b4.b, jLongValue2);
                    }
                    if (((Long) r4.R).longValue() >= 0) {
                        long jLongValue3 = ((Long) r4.R).longValue();
                        c1864b4.e();
                        C2384n4.t0((C2384n4) c1864b4.b, jLongValue3);
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }
}
