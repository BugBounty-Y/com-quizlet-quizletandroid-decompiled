package com.google.android.gms.ads.nonagon.signalgeneration;

import android.os.Binder;
import com.google.android.gms.internal.ads.A4;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2922zl;
import com.google.android.gms.internal.ads.El;
import com.google.android.gms.internal.ads.Fv;
import com.google.android.gms.internal.ads.Nv;
import com.google.android.gms.internal.ads.Xv;
import com.google.android.gms.internal.ads.zzbvl;
import com.google.android.gms.internal.ads.zzdyq;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class o implements Fv {
    public final Xv a;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e b;

    public o(Xv xv, com.quizlet.data.repository.folderwithcreatorinclass.e eVar) {
        this.a = xv;
        this.b = eVar;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        com.google.common.util.concurrent.e eVarC;
        zzbvl zzbvlVar = (zzbvl) obj;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.b;
        String str = zzbvlVar.d;
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        if (com.google.android.gms.ads.internal.util.F.d(str)) {
            eVarC = AbstractC2025es.C(new zzdyq(1));
        } else {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u7)).booleanValue()) {
                eVarC = ((C2227jd) eVar.c).d(new A4(6, eVar, zzbvlVar));
            } else {
                eVarC = ((El) eVar.d).c(zzbvlVar);
            }
        }
        return AbstractC2025es.N(AbstractC2025es.A((Nv) AbstractC2025es.O(Nv.t(eVarC), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.D5)).intValue(), TimeUnit.SECONDS, (ScheduledExecutorService) eVar.a), Throwable.class, new C2922zl(eVar, zzbvlVar, Binder.getCallingUid(), 1), (C2227jd) eVar.b), new C1638d(zzbvlVar, 2), this.a);
    }
}
