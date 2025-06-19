package com.google.android.gms.internal.ads;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.wo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2796wo implements Vo {
    public final AtomicReference a = new AtomicReference();
    public final AtomicReference b = new AtomicReference(Boolean.FALSE);
    public final com.google.android.gms.common.util.a c;
    public final Xv d;
    public final Vo e;
    public final long f;
    public final Hk g;

    public C2796wo(Vo vo, long j, com.google.android.gms.common.util.a aVar, Xv xv, Hk hk) {
        this.c = aVar;
        this.e = vo;
        this.f = j;
        this.d = xv;
        this.g = hk;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return this.e.zza();
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        C2753vo c2753vo;
        C2601s7 c2601s7 = AbstractC2773w7.Mb;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            if (((Boolean) rVar.c.a(AbstractC2773w7.Lb)).booleanValue() && !((Boolean) this.b.getAndSet(Boolean.TRUE)).booleanValue()) {
                C2186id c2186id = AbstractC2270kd.d;
                RunnableC2710uo runnableC2710uo = new RunnableC2710uo(this, 0);
                long j = this.f;
                c2186id.scheduleWithFixedDelay(runnableC2710uo, j, j, TimeUnit.MILLISECONDS);
            }
            synchronized (this) {
                try {
                    AtomicReference atomicReference = this.a;
                    C2753vo c2753vo2 = (C2753vo) atomicReference.get();
                    if (c2753vo2 == null) {
                        com.google.common.util.concurrent.e eVarZzb = this.e.zzb();
                        atomicReference.set(new C2753vo(eVarZzb, this.f, this.c));
                        return eVarZzb;
                    }
                    if (((Boolean) this.b.get()).booleanValue() || c2753vo2.b >= c2753vo2.c.elapsedRealtime()) {
                        c2753vo = c2753vo2;
                    } else {
                        com.google.common.util.concurrent.e eVar = c2753vo2.a;
                        Vo vo = this.e;
                        C2753vo c2753vo3 = new C2753vo(vo.zzb(), this.f, this.c);
                        this.a.set(c2753vo3);
                        if (((Boolean) rVar.c.a(AbstractC2773w7.Nb)).booleanValue()) {
                            if (((Boolean) rVar.c.a(AbstractC2773w7.Ob)).booleanValue()) {
                                Fi fiA = this.g.a();
                                fiA.o("action", "scs");
                                fiA.o("sid", String.valueOf(vo.zza()));
                                fiA.x();
                            }
                            return eVar;
                        }
                        c2753vo = c2753vo3;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        } else {
            AtomicReference atomicReference2 = this.a;
            c2753vo = (C2753vo) atomicReference2.get();
            if (c2753vo == null || c2753vo.b < c2753vo.c.elapsedRealtime()) {
                Vo vo2 = this.e;
                C2753vo c2753vo4 = new C2753vo(vo2.zzb(), this.f, this.c);
                atomicReference2.set(c2753vo4);
                c2753vo = c2753vo4;
            }
        }
        return c2753vo.a;
    }
}
