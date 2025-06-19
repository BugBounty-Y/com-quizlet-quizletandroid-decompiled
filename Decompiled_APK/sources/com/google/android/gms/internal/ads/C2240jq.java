package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.jq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2240jq implements CC {
    public final /* synthetic */ int a;

    public /* synthetic */ C2240jq(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Xv c1942cw;
        switch (this.a) {
            case 0:
                C2198iq c2198iq = new C2198iq();
                try {
                    AbstractC2675tw.a();
                } catch (GeneralSecurityException e) {
                    com.google.android.gms.ads.internal.util.A.l("Failed to Configure Aead. ".concat(e.toString()));
                    com.google.android.gms.ads.internal.j.C.h.h("CryptoUtils.registerAead", e);
                }
                return c2198iq;
            case 1:
                return new C2283kq();
            case 2:
                return com.google.android.gms.common.util.b.a;
            case 3:
                C2498pq c2498pq = new C2498pq();
                c2498pq.a = null;
                return c2498pq;
            case 4:
                return new Aq();
            case 5:
                C2227jd c2227jd = AbstractC2270kd.f;
                AbstractC1981ds.s(c2227jd);
                return c2227jd;
            case 6:
                ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue(), Executors.defaultThreadFactory());
                threadPoolExecutor.allowCoreThreadTimeOut(true);
                ExecutorService executorServiceUnconfigurableExecutorService = Executors.unconfigurableExecutorService(threadPoolExecutor);
                if (executorServiceUnconfigurableExecutorService instanceof Xv) {
                    c1942cw = (Xv) executorServiceUnconfigurableExecutorService;
                } else {
                    c1942cw = executorServiceUnconfigurableExecutorService instanceof ScheduledExecutorService ? new C1942cw((ScheduledExecutorService) executorServiceUnconfigurableExecutorService) : new C2227jd(executorServiceUnconfigurableExecutorService);
                }
                AbstractC1981ds.s(c1942cw);
                return c1942cw;
            case 7:
                C1942cw c1942cw2 = AbstractC2270kd.e;
                AbstractC1981ds.s(c1942cw2);
                return c1942cw2;
            case 8:
                C2227jd c2227jd2 = AbstractC2270kd.f;
                AbstractC1981ds.s(c2227jd2);
                return c2227jd2;
            default:
                return new ThreadFactoryC1733Mc(1);
        }
    }
}
