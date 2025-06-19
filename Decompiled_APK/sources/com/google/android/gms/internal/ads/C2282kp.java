package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.kp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2282kp implements Vo {
    public final C2010ed a;
    public final boolean b;
    public final boolean c;
    public final ScheduledExecutorService d;
    public final C2227jd e;
    public final int f;
    public final int g;

    public C2282kp(C2010ed c2010ed, boolean z, boolean z2, C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, int i, int i2) {
        this.a = c2010ed;
        this.b = z;
        this.c = z2;
        this.e = c2227jd;
        this.d = scheduledExecutorService;
        this.f = i;
        this.g = i2;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 50;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        C2601s7 c2601s7 = AbstractC2773w7.V6;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if ((!((Boolean) rVar.c.a(c2601s7)).booleanValue() || !this.c) && this.g != 2) {
            C2601s7 c2601s72 = AbstractC2773w7.X6;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (!(((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() ? Arrays.asList(((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Y6)).split(",")).contains(String.valueOf(this.f)) : this.b)) {
                return AbstractC2025es.E(new C1934co(null, 5));
            }
            Tv tv = Tv.b;
            C2853y1 c2853y1 = new C2853y1(14);
            C2227jd c2227jd = this.e;
            return AbstractC2025es.x(AbstractC2025es.O(AbstractC2025es.L(tv, c2853y1, c2227jd), ((Long) AbstractC2216j8.b.o()).longValue(), TimeUnit.MILLISECONDS, this.d), Exception.class, new C1804Yb(this, 6), c2227jd);
        }
        return AbstractC2025es.E(new C1934co(null, 5));
    }
}
