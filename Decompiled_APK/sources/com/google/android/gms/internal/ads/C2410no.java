package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.tasks.Task;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.no, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2410no implements Vo {
    public final C2010ed a;
    public final com.google.android.gms.internal.appset.g b;
    public final ScheduledExecutorService c;
    public final C2227jd d;
    public final Context e;

    public C2410no(Context context, C2010ed c2010ed, ScheduledExecutorService scheduledExecutorService, C2227jd c2227jd) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c3)).booleanValue()) {
            this.b = new com.google.android.gms.internal.appset.g(context);
        }
        this.e = context;
        this.a = c2010ed;
        this.c = scheduledExecutorService;
        this.d = c2227jd;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 11;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        Task taskB;
        C2601s7 c2601s7 = AbstractC2773w7.Y2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            if (!((Boolean) rVar.c.a(AbstractC2773w7.d3)).booleanValue()) {
                if (!((Boolean) rVar.c.a(AbstractC2773w7.Z2)).booleanValue()) {
                    return AbstractC2025es.L(AbstractC2457os.d(this.b.b()), new C2853y1(11), AbstractC2270kd.g);
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.c3)).booleanValue()) {
                    AbstractC1972di.o(this.e, false);
                    synchronized (AbstractC1972di.K) {
                        taskB = AbstractC1972di.I;
                    }
                } else {
                    taskB = this.b.b();
                }
                if (taskB == null) {
                    return AbstractC2025es.E(new C2453oo(null, -1, 0));
                }
                com.google.common.util.concurrent.e eVarN = AbstractC2025es.N(AbstractC2457os.d(taskB), new C2487pf(10), AbstractC2270kd.g);
                if (((Boolean) rVar.c.a(AbstractC2773w7.a3)).booleanValue()) {
                    eVarN = AbstractC2025es.O(eVarN, ((Long) rVar.c.a(AbstractC2773w7.b3)).longValue(), TimeUnit.MILLISECONDS, this.c);
                }
                return AbstractC2025es.x(eVarN, Exception.class, new C1804Yb(this, 4), this.d);
            }
        }
        return AbstractC2025es.E(new C2453oo(null, -1, 0));
    }
}
