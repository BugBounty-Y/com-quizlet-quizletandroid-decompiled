package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class Fg implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;
    public final C1741Ne c;
    public final BC d;

    public /* synthetic */ Fg(C1741Ne c1741Ne, C1741Ne c1741Ne2, BC bc, int i) {
        this.a = i;
        this.b = c1741Ne;
        this.c = c1741Ne2;
        this.d = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Context contextA = this.b.a();
                Uq uq = (Uq) this.d.zzb();
                VersionInfoParcel versionInfoParcelB = this.c.b();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new Eg(contextA, uq, versionInfoParcelB, c2227jd);
            case 1:
                C2267ka c2267kaD = new com.quizlet.data.repository.studysetwithcreator.d(2).d(this.b.a(), this.c.b(), (Uq) this.d.zzb());
                AbstractC1981ds.s(c2267kaD);
                return c2267kaD;
            default:
                return new Uq(this.b.a(), this.c.b(), (C2620sk) this.d.zzb(), new L9(15));
        }
    }

    public Fg(C1741Ne c1741Ne, BC bc, C1741Ne c1741Ne2) {
        this.a = 0;
        this.b = c1741Ne;
        this.d = bc;
        this.c = c1741Ne2;
    }
}
