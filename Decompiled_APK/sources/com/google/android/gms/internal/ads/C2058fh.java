package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.fh, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2058fh extends AbstractC2863yB implements InterfaceC1884bh {
    public final ScheduledExecutorService c;
    public ScheduledFuture d;
    public boolean e;

    public C2058fh(C2014eh c2014eh, Set set, Xv xv, ScheduledExecutorService scheduledExecutorService) {
        super(set);
        this.e = false;
        this.c = scheduledExecutorService;
        i1(c2014eh, xv);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    public final void E(zzdgh zzdghVar) {
        if (this.e) {
            return;
        }
        ScheduledFuture scheduledFuture = this.d;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        j1(new C2881yn(zzdghVar, 13));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    public final void a0(zze zzeVar) {
        j1(new S4(zzeVar, 12));
    }

    public final void f() {
        this.d = this.c.schedule(new RunnableC1989e(this, 28), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ia)).intValue(), TimeUnit.MILLISECONDS);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    public final void j() {
        j1(new C1927ch(0));
    }
}
