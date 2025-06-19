package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.zzm;

/* loaded from: classes2.dex */
public final class Uk implements Rk {
    public final long a;
    public final On b;

    public Uk(long j, Context context, S4 s4, C1765Re c1765Re, String str) {
        this.a = j;
        C1765Re c1765Re2 = c1765Re.b;
        com.google.android.gms.ads.internal.client.zzr zzrVar = new com.google.android.gms.ads.internal.client.zzr();
        str.getClass();
        On on = (On) ((BC) new S4(c1765Re2, context, str, zzrVar).b).zzb();
        this.b = on;
        on.N1(new Tk(this, s4));
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void a() {
        this.b.s1(new com.google.android.gms.dynamic.b(null));
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void b(zzm zzmVar) {
        this.b.I2(zzmVar);
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void zza() {
        this.b.y();
    }
}
