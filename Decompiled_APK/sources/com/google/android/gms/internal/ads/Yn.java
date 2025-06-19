package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class Yn implements Vo {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ Yn(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 4;
            case 1:
                return 10;
            case 2:
                return 54;
            case 3:
                return 21;
            case 4:
                return 60;
            case 5:
                return 23;
            case 6:
                return 41;
            default:
                return 48;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        switch (this.a) {
            case 0:
                return AbstractC2025es.E(new Zn((C2023eq) this.c, ((com.google.android.gms.common.util.a) this.b).currentTimeMillis()));
            case 1:
                return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X2)).booleanValue() ? AbstractC2025es.E(new C2109go(1, null)) : AbstractC2025es.L(((C2010ed) this.c).e(), new C2853y1(10), (Xv) this.b);
            case 2:
                return ((C2227jd) this.b).d(new Q4(this, 12));
            case 3:
                return ((C2227jd) this.b).d(new Q4(this, 18));
            case 4:
                com.google.android.gms.ads.internal.util.A.l("HsdpMigrationSignal.produce");
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Lc)).booleanValue()) {
                    return AbstractC2025es.E(new Fo(1, null));
                }
                boolean z = false;
                try {
                    if (((Intent) this.c).resolveActivity(((Context) this.b).getPackageManager()) != null) {
                        com.google.android.gms.ads.internal.util.A.l("HSDP intent is supported");
                        z = true;
                    }
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.j.C.h.h("HsdpMigrationSignal.isHsdpMigrationSupported", e);
                }
                return AbstractC2025es.E(new Fo(1, Boolean.valueOf(z)));
            case 5:
                return ((C2227jd) this.b).d(new Q4(this, 20));
            case 6:
                Tv tvE = AbstractC2025es.E((String) this.c);
                C2853y1 c2853y1 = new C2853y1(12);
                Xv xv = (Xv) this.b;
                return AbstractC2025es.A(AbstractC2025es.L(tvE, c2853y1, xv), Throwable.class, new D9(this, 11), xv);
            default:
                return ((C2227jd) this.b).d(new CallableC2154hp(this, 1));
        }
    }

    public Yn(VersionInfoParcel versionInfoParcel, C2227jd c2227jd) {
        this.a = 2;
        this.c = versionInfoParcel;
        this.b = c2227jd;
    }
}
