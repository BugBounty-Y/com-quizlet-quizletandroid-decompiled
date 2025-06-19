package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.Oe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1747Oe implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;
    public final BC c;

    public /* synthetic */ C1747Oe(C1741Ne c1741Ne, BC bc, int i) {
        this.a = i;
        this.b = c1741Ne;
        this.c = bc;
    }

    public Yn a() {
        return new Yn(4, this.b.a(), (Intent) this.c.zzb());
    }

    public com.quizlet.data.repository.studysetwithcreatorinclass.g b() {
        Context contextA = this.b.a();
        Uq uq = (Uq) this.c.zzb();
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        C2267ka c2267kaE = jVar.r.e(contextA, VersionInfoParcel.a(), uq);
        L9 l9 = AbstractC2224ja.b;
        c2267kaE.getClass();
        return new com.quizlet.data.repository.studysetwithcreatorinclass.g(contextA, jVar.r.e(contextA, VersionInfoParcel.a(), uq).a("google.afma.sdkConstants.getSdkConstants", l9, l9), VersionInfoParcel.a());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                try {
                    return com.google.android.gms.common.wrappers.c.a(this.b.a()).c(((ApplicationInfo) this.c.zzb()).packageName, 0);
                } catch (PackageManager.NameNotFoundException unused) {
                    return null;
                }
            case 1:
                return b();
            case 2:
                return new C1706Hf(this.b.a(), (C5) this.c.zzb());
            case 3:
                return new C2836xl(this.b.a(), (Hk) this.c.zzb());
            case 4:
                return new Kl(this.b.a(), (C1739Nc) this.c.zzb());
            case 5:
                return a();
            case 6:
                C1739Nc c1739Nc = (C1739Nc) this.c.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2021eo(c1739Nc, c2227jd, this.b.a(), 3);
            case 7:
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.c.zzb();
                this.b.a();
                return new Un(scheduledExecutorService, 6);
            case 8:
                return new Nq(this.b.a(), (Tq) this.c.zzb());
            default:
                return new Fi(this.b.a(), (Hk) this.c.zzb());
        }
    }

    public /* synthetic */ C1747Oe(BC bc, C1741Ne c1741Ne, int i) {
        this.a = i;
        this.c = bc;
        this.b = c1741Ne;
    }
}
