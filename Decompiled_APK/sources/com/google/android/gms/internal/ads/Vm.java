package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class Vm implements CC {
    public final /* synthetic */ int a = 1;
    public final BC b;
    public final DC c;
    public final C1741Ne d;

    public Vm(BC bc, C1741Ne c1741Ne, DC dc) {
        this.b = bc;
        this.d = c1741Ne;
        this.c = dc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Context context = (Context) this.b.zzb();
                VersionInfoParcel versionInfoParcelB = this.d.b();
                C1813Ze c1813Ze = (C1813Ze) this.c.a;
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new Om(context, versionInfoParcelB, c1813Ze, c2227jd);
            default:
                return new Om((Context) this.b.zzb(), (C1759Qe) this.c.a, this.d.b());
        }
    }

    public Vm(BC bc, DC dc, C1741Ne c1741Ne) {
        this.b = bc;
        this.c = dc;
        this.d = c1741Ne;
    }
}
