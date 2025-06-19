package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzm;

/* loaded from: classes2.dex */
public final class In extends com.google.android.gms.ads.internal.client.C {
    public final C2326lq a;

    public In(Context context, C1765Re c1765Re, C1979dq c1979dq, C1929cj c1929cj, InterfaceC1622x interfaceC1622x) {
        C2326lq c2326lq = new C2326lq(c1929cj, (Hk) c1765Re.x.zzb());
        ((Ln) c2326lq.c).a.set(interfaceC1622x);
        C2084g6 c2084g6 = new C2084g6();
        c2084g6.b = c1765Re;
        c2084g6.e = context;
        c2084g6.c = c2326lq;
        c2084g6.a = c1979dq;
        c2084g6.d = c1765Re.c();
        c1979dq.r = (Ln) c2326lq.c;
        this.a = new C2326lq(22, c2084g6, c1979dq.c);
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final synchronized void B0(zzm zzmVar, int i) {
        this.a.t(zzmVar, i);
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final void D0(zzm zzmVar) {
        this.a.t(zzmVar, 1);
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final synchronized String f() {
        String str;
        C2326lq c2326lq = this.a;
        synchronized (c2326lq) {
            try {
                Ug ug = (Ug) c2326lq.d;
                str = ug != null ? ug.a : null;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        return str;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0014  */
    @Override // com.google.android.gms.ads.internal.client.D
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean f2() {
        /*
            r2 = this;
            monitor-enter(r2)
            com.google.android.gms.internal.ads.lq r0 = r2.a     // Catch: java.lang.Throwable -> L1c
            monitor-enter(r0)     // Catch: java.lang.Throwable -> L1c
            java.lang.Object r1 = r0.b     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.internal.ads.g6 r1 = (com.google.android.gms.internal.ads.C2084g6) r1     // Catch: java.lang.Throwable -> L1a
            java.lang.Object r1 = r1.f     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.internal.ads.tg r1 = (com.google.android.gms.internal.ads.C2659tg) r1     // Catch: java.lang.Throwable -> L1a
            if (r1 == 0) goto L14
            boolean r1 = r1.c     // Catch: java.lang.Throwable -> L1a
            if (r1 == 0) goto L14
            r1 = 1
            goto L15
        L14:
            r1 = 0
        L15:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L1c
            monitor-exit(r2)
            return r1
        L18:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L1a
            throw r1     // Catch: java.lang.Throwable -> L1c
        L1a:
            r1 = move-exception
            goto L18
        L1c:
            r0 = move-exception
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L1c
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.In.f2():boolean");
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final synchronized String zze() {
        String str;
        C2326lq c2326lq = this.a;
        synchronized (c2326lq) {
            try {
                Ug ug = (Ug) c2326lq.d;
                str = ug != null ? ug.a : null;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        return str;
    }
}
