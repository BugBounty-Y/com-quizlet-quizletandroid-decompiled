package com.google.firebase.perf.transport;

import androidx.camera.camera2.internal.C0148z;
import com.google.firebase.perf.config.RemoteConfigManager;
import com.google.firebase.perf.config.g;
import com.google.firebase.perf.config.h;
import com.google.firebase.perf.config.s;
import com.google.firebase.perf.config.t;
import com.google.firebase.perf.util.Timer;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class c {
    public static final long i;
    public C0148z b;
    public final C0148z e;
    public final C0148z f;
    public final long g;
    public final long h;
    public long c = 500;
    public double d = 500;
    public Timer a = new Timer();

    static {
        com.google.firebase.perf.logging.a.d();
        i = TimeUnit.SECONDS.toMicros(1L);
    }

    public c(C0148z c0148z, assistantMode.utils.studiableMetadata.b bVar, com.google.firebase.perf.config.a aVar, String str) {
        h hVar;
        long jLongValue;
        g gVar;
        long jLongValue2;
        s sVar;
        t tVar;
        this.b = c0148z;
        long jK = str == "Trace" ? aVar.k() : aVar.k();
        if (str == "Trace") {
            synchronized (t.class) {
                try {
                    if (t.b == null) {
                        t.b = new t();
                    }
                    tVar = t.b;
                } finally {
                }
            }
            RemoteConfigManager remoteConfigManager = aVar.a;
            tVar.getClass();
            com.google.firebase.perf.util.d dVar = remoteConfigManager.getLong("fpr_rl_trace_event_count_fg");
            if (dVar.b() && com.google.firebase.perf.config.a.l(((Long) dVar.a()).longValue())) {
                aVar.c.d(((Long) dVar.a()).longValue(), "com.google.firebase.perf.TraceEventCountForeground");
                jLongValue = ((Long) dVar.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVarC = aVar.c(tVar);
                jLongValue = (dVarC.b() && com.google.firebase.perf.config.a.l(((Long) dVarC.a()).longValue())) ? ((Long) dVarC.a()).longValue() : 300L;
            }
        } else {
            synchronized (h.class) {
                try {
                    if (h.b == null) {
                        h.b = new h();
                    }
                    hVar = h.b;
                } finally {
                }
            }
            RemoteConfigManager remoteConfigManager2 = aVar.a;
            hVar.getClass();
            com.google.firebase.perf.util.d dVar2 = remoteConfigManager2.getLong("fpr_rl_network_event_count_fg");
            if (dVar2.b() && com.google.firebase.perf.config.a.l(((Long) dVar2.a()).longValue())) {
                aVar.c.d(((Long) dVar2.a()).longValue(), "com.google.firebase.perf.NetworkEventCountForeground");
                jLongValue = ((Long) dVar2.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVarC2 = aVar.c(hVar);
                jLongValue = (dVarC2.b() && com.google.firebase.perf.config.a.l(((Long) dVarC2.a()).longValue())) ? ((Long) dVarC2.a()).longValue() : 700L;
            }
        }
        long j = jLongValue;
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.e = new C0148z(j, jK, timeUnit);
        this.g = j;
        long jK2 = str == "Trace" ? aVar.k() : aVar.k();
        if (str == "Trace") {
            synchronized (s.class) {
                try {
                    if (s.b == null) {
                        s.b = new s();
                    }
                    sVar = s.b;
                } finally {
                }
            }
            RemoteConfigManager remoteConfigManager3 = aVar.a;
            sVar.getClass();
            com.google.firebase.perf.util.d dVar3 = remoteConfigManager3.getLong("fpr_rl_trace_event_count_bg");
            if (dVar3.b() && com.google.firebase.perf.config.a.l(((Long) dVar3.a()).longValue())) {
                aVar.c.d(((Long) dVar3.a()).longValue(), "com.google.firebase.perf.TraceEventCountBackground");
                jLongValue2 = ((Long) dVar3.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVarC3 = aVar.c(sVar);
                jLongValue2 = (dVarC3.b() && com.google.firebase.perf.config.a.l(((Long) dVarC3.a()).longValue())) ? ((Long) dVarC3.a()).longValue() : 30L;
            }
        } else {
            synchronized (g.class) {
                try {
                    if (g.b == null) {
                        g.b = new g();
                    }
                    gVar = g.b;
                } finally {
                }
            }
            RemoteConfigManager remoteConfigManager4 = aVar.a;
            gVar.getClass();
            com.google.firebase.perf.util.d dVar4 = remoteConfigManager4.getLong("fpr_rl_network_event_count_bg");
            if (dVar4.b() && com.google.firebase.perf.config.a.l(((Long) dVar4.a()).longValue())) {
                aVar.c.d(((Long) dVar4.a()).longValue(), "com.google.firebase.perf.NetworkEventCountBackground");
                jLongValue2 = ((Long) dVar4.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVarC4 = aVar.c(gVar);
                jLongValue2 = (dVarC4.b() && com.google.firebase.perf.config.a.l(((Long) dVarC4.a()).longValue())) ? ((Long) dVarC4.a()).longValue() : 70L;
            }
        }
        long j2 = jLongValue2;
        this.f = new C0148z(j2, jK2, timeUnit);
        this.h = j2;
    }

    public final synchronized void a(boolean z) {
        try {
            this.b = z ? this.e : this.f;
            this.c = z ? this.g : this.h;
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0065 A[Catch: all -> 0x0074, TryCatch #0 {all -> 0x0074, blocks: (B:3:0x0001, B:9:0x0031, B:14:0x005a, B:16:0x0065, B:19:0x0076, B:21:0x007e, B:10:0x0039, B:11:0x0042, B:12:0x0046, B:13:0x0050), top: B:29:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x007e A[Catch: all -> 0x0074, TRY_LEAVE, TryCatch #0 {all -> 0x0074, blocks: (B:3:0x0001, B:9:0x0031, B:14:0x005a, B:16:0x0065, B:19:0x0076, B:21:0x007e, B:10:0x0039, B:11:0x0042, B:12:0x0046, B:13:0x0050), top: B:29:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0083 A[DONT_GENERATE] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean b() {
        /*
            r13 = this;
            monitor-enter(r13)
            com.google.firebase.perf.util.Timer r0 = new com.google.firebase.perf.util.Timer     // Catch: java.lang.Throwable -> L74
            r0.<init>()     // Catch: java.lang.Throwable -> L74
            com.google.firebase.perf.util.Timer r1 = r13.a     // Catch: java.lang.Throwable -> L74
            r1.getClass()     // Catch: java.lang.Throwable -> L74
            long r2 = r0.b     // Catch: java.lang.Throwable -> L74
            long r4 = r1.b     // Catch: java.lang.Throwable -> L74
            long r2 = r2 - r4
            double r1 = (double) r2     // Catch: java.lang.Throwable -> L74
            androidx.camera.camera2.internal.z r3 = r13.b     // Catch: java.lang.Throwable -> L74
            r3.getClass()     // Catch: java.lang.Throwable -> L74
            int[] r4 = com.google.firebase.perf.util.f.a     // Catch: java.lang.Throwable -> L74
            java.lang.Object r5 = r3.d     // Catch: java.lang.Throwable -> L74
            java.util.concurrent.TimeUnit r5 = (java.util.concurrent.TimeUnit) r5     // Catch: java.lang.Throwable -> L74
            int r6 = r5.ordinal()     // Catch: java.lang.Throwable -> L74
            r4 = r4[r6]     // Catch: java.lang.Throwable -> L74
            long r6 = r3.c     // Catch: java.lang.Throwable -> L74
            long r8 = r3.b     // Catch: java.lang.Throwable -> L74
            r3 = 1
            r10 = 1
            if (r4 == r3) goto L50
            r12 = 2
            if (r4 == r12) goto L46
            r12 = 3
            if (r4 == r12) goto L39
            double r8 = (double) r8     // Catch: java.lang.Throwable -> L74
            long r4 = r5.toSeconds(r6)     // Catch: java.lang.Throwable -> L74
            double r4 = (double) r4     // Catch: java.lang.Throwable -> L74
            double r8 = r8 / r4
            goto L5a
        L39:
            double r4 = (double) r8     // Catch: java.lang.Throwable -> L74
            double r6 = (double) r6     // Catch: java.lang.Throwable -> L74
            double r4 = r4 / r6
            java.util.concurrent.TimeUnit r6 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L74
            long r6 = r6.toMillis(r10)     // Catch: java.lang.Throwable -> L74
        L42:
            double r6 = (double) r6     // Catch: java.lang.Throwable -> L74
            double r8 = r4 * r6
            goto L5a
        L46:
            double r4 = (double) r8     // Catch: java.lang.Throwable -> L74
            double r6 = (double) r6     // Catch: java.lang.Throwable -> L74
            double r4 = r4 / r6
            java.util.concurrent.TimeUnit r6 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L74
            long r6 = r6.toMicros(r10)     // Catch: java.lang.Throwable -> L74
            goto L42
        L50:
            double r4 = (double) r8     // Catch: java.lang.Throwable -> L74
            double r6 = (double) r6     // Catch: java.lang.Throwable -> L74
            double r4 = r4 / r6
            java.util.concurrent.TimeUnit r6 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L74
            long r6 = r6.toNanos(r10)     // Catch: java.lang.Throwable -> L74
            goto L42
        L5a:
            double r1 = r1 * r8
            long r4 = com.google.firebase.perf.transport.c.i     // Catch: java.lang.Throwable -> L74
            double r4 = (double) r4     // Catch: java.lang.Throwable -> L74
            double r1 = r1 / r4
            r4 = 0
            int r4 = (r1 > r4 ? 1 : (r1 == r4 ? 0 : -1))
            if (r4 <= 0) goto L76
            double r4 = r13.d     // Catch: java.lang.Throwable -> L74
            double r4 = r4 + r1
            long r1 = r13.c     // Catch: java.lang.Throwable -> L74
            double r1 = (double) r1     // Catch: java.lang.Throwable -> L74
            double r1 = java.lang.Math.min(r4, r1)     // Catch: java.lang.Throwable -> L74
            r13.d = r1     // Catch: java.lang.Throwable -> L74
            r13.a = r0     // Catch: java.lang.Throwable -> L74
            goto L76
        L74:
            r0 = move-exception
            goto L86
        L76:
            double r0 = r13.d     // Catch: java.lang.Throwable -> L74
            r4 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            int r2 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1))
            if (r2 < 0) goto L83
            double r0 = r0 - r4
            r13.d = r0     // Catch: java.lang.Throwable -> L74
            monitor-exit(r13)
            return r3
        L83:
            monitor-exit(r13)
            r0 = 0
            return r0
        L86:
            monitor-exit(r13)     // Catch: java.lang.Throwable -> L74
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.transport.c.b():boolean");
    }
}
