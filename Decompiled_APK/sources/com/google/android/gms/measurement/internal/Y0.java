package com.google.android.gms.measurement.internal;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Looper;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Y0 extends AbstractC3888q {
    public final X0 d;
    public InterfaceC3897v e;
    public volatile Boolean f;
    public final V0 g;
    public ScheduledExecutorService h;
    public final androidx.compose.foundation.gestures.l1 i;
    public final ArrayList j;
    public final V0 k;

    public Y0(Y y) {
        super(y);
        this.j = new ArrayList();
        this.i = new androidx.compose.foundation.gestures.l1(y.n);
        this.d = new X0(this);
        this.g = new V0(this, y, 0);
        this.k = new V0(this, y, 1);
    }

    public static void k0(Y0 y0, ComponentName componentName) {
        y0.S();
        if (y0.e != null) {
            y0.e = null;
            I i = ((Y) y0.b).i;
            Y.k(i);
            i.o.g("Disconnected from device MeasurementService", componentName);
            y0.S();
            y0.V();
        }
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return false;
    }

    public final void V() {
        S();
        Q();
        if (b0()) {
            return;
        }
        if (e0()) {
            X0 x0 = this.d;
            Y0 y0 = x0.c;
            y0.S();
            Context context = ((Y) y0.b).a;
            synchronized (x0) {
                try {
                    if (x0.a) {
                        I i = ((Y) x0.c.b).i;
                        Y.k(i);
                        i.o.f("Connection attempt already in progress");
                        return;
                    } else {
                        if (x0.b != null && (x0.b.r() || x0.b.q())) {
                            I i2 = ((Y) x0.c.b).i;
                            Y.k(i2);
                            i2.o.f("Already awaiting connection attempt");
                            return;
                        }
                        x0.b = new E(93, context, Looper.getMainLooper(), x0, x0);
                        I i3 = ((Y) x0.c.b).i;
                        Y.k(i3);
                        i3.o.f("Connecting to remote service");
                        x0.a = true;
                        com.google.android.gms.common.internal.u.h(x0.b);
                        x0.b.c();
                        return;
                    }
                } finally {
                }
            }
        }
        Y y = (Y) this.b;
        if (y.g.V()) {
            return;
        }
        List<ResolveInfo> listQueryIntentServices = y.a.getPackageManager().queryIntentServices(new Intent().setClassName(y.a, "com.google.android.gms.measurement.AppMeasurementService"), 65536);
        if (listQueryIntentServices == null || listQueryIntentServices.isEmpty()) {
            I i4 = y.i;
            Y.k(i4);
            i4.g.f("Unable to use remote or local measurement implementation. Please register the AppMeasurementService service in the app manifest");
            return;
        }
        Intent intent = new Intent("com.google.android.gms.measurement.START");
        intent.setComponent(new ComponentName(y.a, "com.google.android.gms.measurement.AppMeasurementService"));
        X0 x02 = this.d;
        Y0 y02 = x02.c;
        y02.S();
        Context context2 = ((Y) y02.b).a;
        com.google.android.gms.common.stats.a aVarB = com.google.android.gms.common.stats.a.b();
        synchronized (x02) {
            try {
                if (x02.a) {
                    I i5 = ((Y) x02.c.b).i;
                    Y.k(i5);
                    i5.o.f("Connection attempt already in progress");
                } else {
                    Y0 y03 = x02.c;
                    I i6 = ((Y) y03.b).i;
                    Y.k(i6);
                    i6.o.f("Using local app measurement service");
                    x02.a = true;
                    aVarB.a(context2, intent, y03.d, 129);
                }
            } finally {
            }
        }
    }

    public final void W() {
        S();
        Q();
        X0 x0 = this.d;
        if (x0.b != null && (x0.b.q() || x0.b.r())) {
            x0.b.e();
        }
        x0.b = null;
        try {
            com.google.android.gms.common.stats.a.b().c(((Y) this.b).a, x0);
        } catch (IllegalArgumentException | IllegalStateException unused) {
        }
        this.e = null;
    }

    public final void X(AtomicReference atomicReference) {
        S();
        Q();
        i0(new Q0(this, atomicReference, f0(false), 1));
    }

    /* JADX WARN: Removed duplicated region for block: B:173:0x02c5 A[Catch: all -> 0x01e2, SQLiteException -> 0x02a1, SQLiteDatabaseLockedException -> 0x02a6, SQLiteFullException -> 0x02aa, TryCatch #36 {all -> 0x01e2, blocks: (B:95:0x01bb, B:99:0x01d1, B:101:0x01d6, B:117:0x01fe, B:118:0x0201, B:116:0x01fa, B:126:0x0214, B:128:0x0228, B:135:0x023e, B:136:0x0247, B:137:0x024a, B:133:0x0238, B:140:0x024e, B:142:0x0262, B:149:0x0278, B:150:0x0282, B:151:0x0285, B:147:0x0272, B:154:0x0289, B:158:0x029d, B:173:0x02c5, B:174:0x02cf, B:175:0x02d2, B:171:0x02bf, B:183:0x02df, B:184:0x02ea, B:213:0x0374), top: B:392:0x01bb }] */
    /* JADX WARN: Removed duplicated region for block: B:254:0x041b A[Catch: all -> 0x03a0, TRY_ENTER, TryCatch #0 {all -> 0x03a0, blocks: (B:264:0x0447, B:254:0x041b, B:256:0x0421, B:257:0x0424, B:272:0x0465, B:215:0x038b, B:217:0x0395, B:224:0x03a8), top: B:370:0x0447 }] */
    /* JADX WARN: Removed duplicated region for block: B:259:0x0433  */
    /* JADX WARN: Removed duplicated region for block: B:267:0x044e  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x0453 A[PHI: r8 r13 r23 r25 r27 r34 r35
  0x0453: PHI (r8v5 int) = (r8v3 int), (r8v3 int), (r8v6 int) binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r13v15 android.database.sqlite.SQLiteDatabase) = 
  (r13v10 android.database.sqlite.SQLiteDatabase)
  (r13v11 android.database.sqlite.SQLiteDatabase)
  (r13v16 android.database.sqlite.SQLiteDatabase)
 binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r23v9 java.lang.String) = (r23v6 java.lang.String), (r23v7 java.lang.String), (r23v10 java.lang.String) binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r25v9 java.lang.String) = (r25v6 java.lang.String), (r25v7 java.lang.String), (r25v10 java.lang.String) binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r27v11 com.google.android.gms.measurement.internal.Y) = 
  (r27v8 com.google.android.gms.measurement.internal.Y)
  (r27v9 com.google.android.gms.measurement.internal.Y)
  (r27v12 com.google.android.gms.measurement.internal.Y)
 binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r34v9 int) = (r34v6 int), (r34v7 int), (r34v10 int) binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]
  0x0453: PHI (r35v9 java.lang.String) = (r35v6 java.lang.String), (r35v7 java.lang.String), (r35v10 java.lang.String) binds: [B:260:0x0436, B:275:0x0477, B:268:0x0451] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:274:0x0474  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x0489  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x048e  */
    /* JADX WARN: Removed duplicated region for block: B:286:0x04aa  */
    /* JADX WARN: Removed duplicated region for block: B:287:0x04b3  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x04d9  */
    /* JADX WARN: Removed duplicated region for block: B:299:0x057b  */
    /* JADX WARN: Removed duplicated region for block: B:332:0x0614  */
    /* JADX WARN: Removed duplicated region for block: B:336:0x061c  */
    /* JADX WARN: Removed duplicated region for block: B:451:0x047a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:452:0x047a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:454:0x047a A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Y(com.google.android.gms.measurement.internal.InterfaceC3897v r64, com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable r65, com.google.android.gms.measurement.internal.zzr r66) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1718
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.Y0.Y(com.google.android.gms.measurement.internal.v, com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable, com.google.android.gms.measurement.internal.zzr):void");
    }

    public final void Z(zzai zzaiVar) {
        boolean zY;
        S();
        Q();
        Y y = (Y) this.b;
        y.getClass();
        C cO = y.o();
        Y y2 = (Y) cO.b;
        Y.h(y2.l);
        byte[] bArrR0 = x1.R0(zzaiVar);
        if (bArrR0.length > 131072) {
            I i = y2.i;
            Y.k(i);
            i.h.f("Conditional user property too long for local database. Sending directly to service");
            zY = false;
        } else {
            zY = cO.Y(2, bArrR0);
        }
        boolean z = zY;
        i0(new com.google.android.gms.cloudmessaging.g(this, f0(true), z, new zzai(zzaiVar), 4));
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0059  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a0(android.os.Bundle r8) {
        /*
            r7 = this;
            r7.S()
            r7.Q()
            com.google.android.gms.measurement.internal.zzbf r4 = new com.google.android.gms.measurement.internal.zzbf
            r4.<init>(r8)
            r7.j0()
            java.lang.Object r0 = r7.b
            com.google.android.gms.measurement.internal.Y r0 = (com.google.android.gms.measurement.internal.Y) r0
            com.google.android.gms.measurement.internal.e r1 = r0.g
            r2 = 0
            com.google.android.gms.measurement.internal.s r3 = com.google.android.gms.measurement.internal.AbstractC3893t.l1
            boolean r1 = r1.f0(r2, r3)
            r2 = 0
            if (r1 == 0) goto L59
            com.google.android.gms.measurement.internal.C r0 = r0.o()
            java.lang.Object r1 = r0.b
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.measurement.internal.x1 r3 = r1.l
            com.google.android.gms.measurement.internal.Y.h(r3)
            byte[] r3 = com.google.android.gms.measurement.internal.x1.R0(r4)
            com.google.android.gms.measurement.internal.I r1 = r1.i
            if (r3 != 0) goto L3f
            com.google.android.gms.measurement.internal.Y.k(r1)
            java.lang.String r0 = "Null default event parameters; not writing to database"
            com.google.android.gms.internal.ads.Ka r1 = r1.h
            r1.f(r0)
        L3d:
            r0 = r2
            goto L54
        L3f:
            int r5 = r3.length
            r6 = 131072(0x20000, float:1.83671E-40)
            if (r5 <= r6) goto L4f
            com.google.android.gms.measurement.internal.Y.k(r1)
            java.lang.String r0 = "Default event parameters too long for local database. Sending directly to service"
            com.google.android.gms.internal.ads.Ka r1 = r1.h
            r1.f(r0)
            goto L3d
        L4f:
            r1 = 4
            boolean r0 = r0.Y(r1, r3)
        L54:
            if (r0 == 0) goto L59
            r0 = 1
            r3 = r0
            goto L5a
        L59:
            r3 = r2
        L5a:
            com.google.android.gms.measurement.internal.zzr r2 = r7.f0(r2)
            com.google.android.gms.measurement.internal.z0 r0 = new com.google.android.gms.measurement.internal.z0
            r1 = r7
            r5 = r8
            r0.<init>(r1, r2, r3, r4, r5)
            r7.i0(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.Y0.a0(android.os.Bundle):void");
    }

    public final boolean b0() {
        S();
        Q();
        return this.e != null;
    }

    public final boolean c0() {
        S();
        Q();
        if (!e0()) {
            return true;
        }
        x1 x1Var = ((Y) this.b).l;
        Y.h(x1Var);
        return x1Var.Y0() >= ((Integer) AbstractC3893t.I0.a(null)).intValue();
    }

    public final boolean d0() {
        S();
        Q();
        if (!e0()) {
            return true;
        }
        x1 x1Var = ((Y) this.b).l;
        Y.h(x1Var);
        return x1Var.Y0() >= 241200;
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0116  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e0() {
        /*
            Method dump skipped, instructions count: 314
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.Y0.e0():boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x00a1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.zzr f0(boolean r11) {
        /*
            r10 = this;
            java.lang.Object r0 = r10.b
            com.google.android.gms.measurement.internal.Y r0 = (com.google.android.gms.measurement.internal.Y) r0
            r0.getClass()
            com.google.android.gms.measurement.internal.A r1 = r0.n()
            r2 = 0
            if (r11 == 0) goto Lb6
            com.google.android.gms.measurement.internal.I r11 = r0.i
            com.google.android.gms.measurement.internal.Y.k(r11)
            java.lang.Object r11 = r11.b
            com.google.android.gms.measurement.internal.Y r11 = (com.google.android.gms.measurement.internal.Y) r11
            com.google.android.gms.measurement.internal.O r0 = r11.h
            com.google.android.gms.measurement.internal.Y.h(r0)
            androidx.work.impl.background.greedy.d r0 = r0.g
            if (r0 != 0) goto L22
            goto Lb6
        L22:
            com.google.android.gms.measurement.internal.O r11 = r11.h
            com.google.android.gms.measurement.internal.Y.h(r11)
            androidx.work.impl.background.greedy.d r11 = r11.g
            java.lang.Object r0 = r11.e
            com.google.android.gms.measurement.internal.O r0 = (com.google.android.gms.measurement.internal.O) r0
            r0.S()
            r0.S()
            java.lang.Object r3 = r11.e
            com.google.android.gms.measurement.internal.O r3 = (com.google.android.gms.measurement.internal.O) r3
            android.content.SharedPreferences r3 = r3.X()
            java.lang.Object r4 = r11.b
            java.lang.String r4 = (java.lang.String) r4
            r5 = 0
            long r3 = r3.getLong(r4, r5)
            int r7 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r7 != 0) goto L4e
            r11.l()
            r3 = r5
            goto L60
        L4e:
            java.lang.Object r7 = r0.b
            com.google.android.gms.measurement.internal.Y r7 = (com.google.android.gms.measurement.internal.Y) r7
            com.google.android.gms.common.util.b r7 = r7.n
            r7.getClass()
            long r7 = java.lang.System.currentTimeMillis()
            long r3 = r3 - r7
            long r3 = java.lang.Math.abs(r3)
        L60:
            long r7 = r11.a
            int r9 = (r3 > r7 ? 1 : (r3 == r7 ? 0 : -1))
            if (r9 >= 0) goto L68
        L66:
            r11 = r2
            goto L9f
        L68:
            long r7 = r7 + r7
            int r3 = (r3 > r7 ? 1 : (r3 == r7 ? 0 : -1))
            if (r3 <= 0) goto L71
            r11.l()
            goto L66
        L71:
            java.lang.Object r3 = r11.d
            java.lang.String r3 = (java.lang.String) r3
            android.content.SharedPreferences r4 = r0.X()
            java.lang.String r3 = r4.getString(r3, r2)
            java.lang.Object r4 = r11.c
            java.lang.String r4 = (java.lang.String) r4
            android.content.SharedPreferences r0 = r0.X()
            long r7 = r0.getLong(r4, r5)
            r11.l()
            if (r3 == 0) goto L9d
            int r11 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r11 > 0) goto L93
            goto L9d
        L93:
            android.util.Pair r11 = new android.util.Pair
            java.lang.Long r0 = java.lang.Long.valueOf(r7)
            r11.<init>(r3, r0)
            goto L9f
        L9d:
            android.util.Pair r11 = com.google.android.gms.measurement.internal.O.B
        L9f:
            if (r11 == 0) goto Lb6
            android.util.Pair r0 = com.google.android.gms.measurement.internal.O.B
            if (r11 != r0) goto La6
            goto Lb6
        La6:
            java.lang.Object r0 = r11.second
            java.lang.String r0 = java.lang.String.valueOf(r0)
            java.lang.Object r11 = r11.first
            java.lang.String r11 = (java.lang.String) r11
            java.lang.String r2 = ":"
            java.lang.String r2 = android.support.v4.media.session.a.l(r0, r2, r11)
        Lb6:
            com.google.android.gms.measurement.internal.zzr r11 = r1.V(r2)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.Y0.f0(boolean):com.google.android.gms.measurement.internal.zzr");
    }

    public final void g0() {
        S();
        Y y = (Y) this.b;
        I i = y.i;
        Y.k(i);
        ArrayList arrayList = this.j;
        i.o.g("Processing queued up service tasks", Integer.valueOf(arrayList.size()));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            try {
                ((Runnable) it2.next()).run();
            } catch (RuntimeException e) {
                I i2 = y.i;
                Y.k(i2);
                i2.g.g("Task exception while flushing queue", e);
            }
        }
        arrayList.clear();
        this.k.a();
    }

    public final void h0() {
        S();
        androidx.compose.foundation.gestures.l1 l1Var = this.i;
        ((com.google.android.gms.common.util.b) l1Var.c).getClass();
        l1Var.b = SystemClock.elapsedRealtime();
        ((Y) this.b).getClass();
        this.g.c(((Long) AbstractC3893t.X.a(null)).longValue());
    }

    public final void i0(Runnable runnable) {
        S();
        if (b0()) {
            runnable.run();
            return;
        }
        ArrayList arrayList = this.j;
        long size = arrayList.size();
        Y y = (Y) this.b;
        y.getClass();
        if (size >= 1000) {
            I i = y.i;
            Y.k(i);
            i.g.f("Discarding data. Max runnable queue size reached");
        } else {
            arrayList.add(runnable);
            this.k.c(60000L);
            V();
        }
    }

    public final void j0() {
        ((Y) this.b).getClass();
    }
}
