package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.C1614q;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.ep, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2022ep implements Vo {
    public final Context a;
    public final ScheduledExecutorService b;
    public final Xv c;
    public final boolean d;
    public final boolean e;

    public C2022ep(L9 l9, Context context, ScheduledExecutorService scheduledExecutorService, Xv xv, int i, boolean z, boolean z2) {
        this.a = context;
        this.b = scheduledExecutorService;
        this.c = xv;
        this.d = z;
        this.e = z2;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 40;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        C2313ld c2313ld = new C2313ld();
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        com.google.android.gms.common.c cVar2 = com.google.android.gms.common.c.b;
        Context context = this.a;
        int iC = cVar2.c(context, 12451000);
        if (iC == 0 || iC == 2) {
            AbstractC2270kd.a.execute(new Qv(13, context, c2313ld));
        }
        Nv nvT = Nv.t(c2313ld);
        final int i = 0;
        InterfaceC2544qt interfaceC2544qt = new InterfaceC2544qt(this) { // from class: com.google.android.gms.internal.ads.dp
            public final /* synthetic */ C2022ep b;

            {
                this.b = this;
            }

            /* JADX WARN: Removed duplicated region for block: B:34:0x005d A[EXC_TOP_SPLITTER, SYNTHETIC] */
            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final java.lang.Object apply(java.lang.Object r9) {
                /*
                    r8 = this;
                    int r0 = r2
                    switch(r0) {
                        case 0: goto L2a;
                        default: goto L5;
                    }
                L5:
                    java.lang.Throwable r9 = (java.lang.Throwable) r9
                    com.google.android.gms.ads.internal.client.q r9 = com.google.android.gms.ads.internal.client.C1614q.f
                    com.google.android.gms.ads.internal.util.client.c r9 = r9.a
                    com.google.android.gms.internal.ads.ep r9 = r8.b
                    android.content.Context r9 = r9.a
                    android.content.ContentResolver r9 = r9.getContentResolver()
                    r0 = 0
                    if (r9 != 0) goto L18
                    r9 = r0
                    goto L1e
                L18:
                    java.lang.String r1 = "android_id"
                    java.lang.String r9 = android.provider.Settings.Secure.getString(r9, r1)
                L1e:
                    com.google.android.gms.internal.ads.Xn r1 = new com.google.android.gms.internal.ads.Xn
                    com.google.android.gms.internal.ads.Ns r2 = new com.google.android.gms.internal.ads.Ns
                    r2.<init>()
                    r3 = 3
                    r1.<init>(r0, r9, r2, r3)
                    return r1
                L2a:
                    com.google.android.gms.internal.ads.ep r0 = r8.b
                    com.google.android.gms.ads.identifier.a r9 = (com.google.android.gms.ads.identifier.a) r9
                    com.google.android.gms.internal.ads.Ns r1 = new com.google.android.gms.internal.ads.Ns
                    r1.<init>()
                    boolean r2 = r0.d
                    if (r2 != 0) goto L4a
                    com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.k3
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
                    com.google.android.gms.internal.ads.u7 r3 = r3.c
                    java.lang.Object r2 = r3.a(r2)
                    java.lang.Boolean r2 = (java.lang.Boolean) r2
                    boolean r2 = r2.booleanValue()
                    if (r2 != 0) goto L5d
                    goto La2
                L4a:
                    com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.l3
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
                    com.google.android.gms.internal.ads.u7 r3 = r3.c
                    java.lang.Object r2 = r3.a(r2)
                    java.lang.Boolean r2 = (java.lang.Boolean) r2
                    boolean r2 = r2.booleanValue()
                    if (r2 != 0) goto L5d
                    goto La2
                L5d:
                    android.content.Context r1 = r0.a     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.Rs r2 = com.google.android.gms.internal.ads.Rs.f(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.util.Objects.requireNonNull(r9)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.String r5 = r9.a     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.util.Objects.requireNonNull(r5)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.String r6 = r1.getPackageName()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.q3     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.u7 r3 = r3.c     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Object r1 = r3.a(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Long r1 = (java.lang.Long) r1     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    long r3 = r1.longValue()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    boolean r7 = r0.e     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    r2.getClass()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Class<com.google.android.gms.internal.ads.Rs> r1 = com.google.android.gms.internal.ads.Rs.class
                    monitor-enter(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.Ns r0 = r2.a(r3, r5, r6, r7)     // Catch: java.lang.Throwable -> L8e
                    monitor-exit(r1)     // Catch: java.lang.Throwable -> L8e
                    r1 = r0
                    goto La2
                L8e:
                    r0 = move-exception
                    monitor-exit(r1)     // Catch: java.lang.Throwable -> L8e
                    throw r0     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                L91:
                    r0 = move-exception
                    goto L94
                L93:
                    r0 = move-exception
                L94:
                    java.lang.String r1 = "AdIdInfoSignalSource.getPaidV1"
                    com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
                    com.google.android.gms.internal.ads.ed r2 = r2.h
                    r2.h(r1, r0)
                    com.google.android.gms.internal.ads.Ns r1 = new com.google.android.gms.internal.ads.Ns
                    r1.<init>()
                La2:
                    com.google.android.gms.internal.ads.Xn r0 = new com.google.android.gms.internal.ads.Xn
                    r2 = 0
                    r3 = 3
                    r0.<init>(r9, r2, r1, r3)
                    return r0
                */
                throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1978dp.apply(java.lang.Object):java.lang.Object");
            }
        };
        Xv xv = this.c;
        final int i2 = 1;
        return AbstractC2025es.x((Nv) AbstractC2025es.O(AbstractC2025es.L(nvT, interfaceC2544qt, xv), ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Z0)).longValue(), TimeUnit.MILLISECONDS, this.b), Throwable.class, new InterfaceC2544qt(this) { // from class: com.google.android.gms.internal.ads.dp
            public final /* synthetic */ C2022ep b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            public final Object apply(Object v) {
                /*
                    this = this;
                    int r0 = r2
                    switch(r0) {
                        case 0: goto L2a;
                        default: goto L5;
                    }
                L5:
                    java.lang.Throwable r9 = (java.lang.Throwable) r9
                    com.google.android.gms.ads.internal.client.q r9 = com.google.android.gms.ads.internal.client.C1614q.f
                    com.google.android.gms.ads.internal.util.client.c r9 = r9.a
                    com.google.android.gms.internal.ads.ep r9 = r8.b
                    android.content.Context r9 = r9.a
                    android.content.ContentResolver r9 = r9.getContentResolver()
                    r0 = 0
                    if (r9 != 0) goto L18
                    r9 = r0
                    goto L1e
                L18:
                    java.lang.String r1 = "android_id"
                    java.lang.String r9 = android.provider.Settings.Secure.getString(r9, r1)
                L1e:
                    com.google.android.gms.internal.ads.Xn r1 = new com.google.android.gms.internal.ads.Xn
                    com.google.android.gms.internal.ads.Ns r2 = new com.google.android.gms.internal.ads.Ns
                    r2.<init>()
                    r3 = 3
                    r1.<init>(r0, r9, r2, r3)
                    return r1
                L2a:
                    com.google.android.gms.internal.ads.ep r0 = r8.b
                    com.google.android.gms.ads.identifier.a r9 = (com.google.android.gms.ads.identifier.a) r9
                    com.google.android.gms.internal.ads.Ns r1 = new com.google.android.gms.internal.ads.Ns
                    r1.<init>()
                    boolean r2 = r0.d
                    if (r2 != 0) goto L4a
                    com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.k3
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
                    com.google.android.gms.internal.ads.u7 r3 = r3.c
                    java.lang.Object r2 = r3.a(r2)
                    java.lang.Boolean r2 = (java.lang.Boolean) r2
                    boolean r2 = r2.booleanValue()
                    if (r2 != 0) goto L5d
                    goto La2
                L4a:
                    com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.l3
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
                    com.google.android.gms.internal.ads.u7 r3 = r3.c
                    java.lang.Object r2 = r3.a(r2)
                    java.lang.Boolean r2 = (java.lang.Boolean) r2
                    boolean r2 = r2.booleanValue()
                    if (r2 != 0) goto L5d
                    goto La2
                L5d:
                    android.content.Context r1 = r0.a     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.Rs r2 = com.google.android.gms.internal.ads.Rs.f(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.util.Objects.requireNonNull(r9)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.String r5 = r9.a     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.util.Objects.requireNonNull(r5)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.String r6 = r1.getPackageName()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.q3     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.u7 r3 = r3.c     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Object r1 = r3.a(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Long r1 = (java.lang.Long) r1     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    long r3 = r1.longValue()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    boolean r7 = r0.e     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    r2.getClass()     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    java.lang.Class<com.google.android.gms.internal.ads.Rs> r1 = com.google.android.gms.internal.ads.Rs.class
                    monitor-enter(r1)     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                    com.google.android.gms.internal.ads.Ns r0 = r2.a(r3, r5, r6, r7)     // Catch: java.lang.Throwable -> L8e
                    monitor-exit(r1)     // Catch: java.lang.Throwable -> L8e
                    r1 = r0
                    goto La2
                L8e:
                    r0 = move-exception
                    monitor-exit(r1)     // Catch: java.lang.Throwable -> L8e
                    throw r0     // Catch: java.lang.IllegalArgumentException -> L91 java.io.IOException -> L93
                L91:
                    r0 = move-exception
                    goto L94
                L93:
                    r0 = move-exception
                L94:
                    java.lang.String r1 = "AdIdInfoSignalSource.getPaidV1"
                    com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
                    com.google.android.gms.internal.ads.ed r2 = r2.h
                    r2.h(r1, r0)
                    com.google.android.gms.internal.ads.Ns r1 = new com.google.android.gms.internal.ads.Ns
                    r1.<init>()
                La2:
                    com.google.android.gms.internal.ads.Xn r0 = new com.google.android.gms.internal.ads.Xn
                    r2 = 0
                    r3 = 3
                    r0.<init>(r9, r2, r1, r3)
                    return r0
                */
                throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1978dp.apply(java.lang.Object):java.lang.Object");
            }
        }, xv);
    }
}
