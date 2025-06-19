package com.google.android.gms.ads.nonagon.signalgeneration;

import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2318li;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.InterfaceC2618si;

/* loaded from: classes2.dex */
public final class m implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;
    public final BC d;

    public /* synthetic */ m(BC bc, BC bc2, BC bc3, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                InterfaceC2618si interfaceC2618si = (G) this.b.zzb();
                InterfaceC2618si interfaceC2618si2 = (r) this.c.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                if (((Integer) this.d.zzb()).intValue() == 2) {
                    interfaceC2618si = interfaceC2618si2;
                }
                return new C2318li(interfaceC2618si, c2227jd);
            default:
                return new r((k) this.b.zzb(), ((Integer) this.c.zzb()).intValue(), (String) this.d.zzb());
        }
    }
}
