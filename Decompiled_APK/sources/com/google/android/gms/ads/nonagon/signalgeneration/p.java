package com.google.android.gms.ads.nonagon.signalgeneration;

import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C1703Hc;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.HC;
import com.google.android.gms.internal.ads.Kk;

/* loaded from: classes2.dex */
public final class p implements CC {
    public final /* synthetic */ int a;
    public final HC b;

    public /* synthetic */ p(HC hc, int i) {
        this.a = i;
        this.b = hc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new o(c2227jd, ((C1703Hc) this.b).c());
            default:
                return new F((Kk) ((BC) this.b).zzb());
        }
    }
}
