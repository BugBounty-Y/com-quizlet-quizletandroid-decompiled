package com.google.firebase.perf.config;

import com.google.android.gms.internal.mlkit_vision_common.D4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class a {
    public static final com.google.firebase.perf.logging.a d = com.google.firebase.perf.logging.a.d();
    public static volatile a e;
    public final RemoteConfigManager a = RemoteConfigManager.getInstance();
    public com.google.firebase.perf.util.c b = new com.google.firebase.perf.util.c();
    public final v c = v.b();

    public static synchronized a e() {
        try {
            if (e == null) {
                e = new a();
            }
        } catch (Throwable th) {
            throw th;
        }
        return e;
    }

    public static boolean l(long j) {
        return j >= 0;
    }

    public static boolean m(String str) {
        if (!str.trim().isEmpty()) {
            for (String str2 : str.split(";")) {
                if (str2.trim().equals("21.0.5")) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean n(long j) {
        return j >= 0;
    }

    public static boolean p(double d2) {
        return 0.0d <= d2 && d2 <= 1.0d;
    }

    public final com.google.firebase.perf.util.d a(D4 d4) {
        v vVar = this.c;
        String strA = d4.a();
        if (strA == null) {
            vVar.getClass();
            v.c.a();
            return new com.google.firebase.perf.util.d();
        }
        if (vVar.a == null) {
            vVar.c(v.a());
            if (vVar.a == null) {
                return new com.google.firebase.perf.util.d();
            }
        }
        if (!vVar.a.contains(strA)) {
            return new com.google.firebase.perf.util.d();
        }
        try {
            return new com.google.firebase.perf.util.d(Boolean.valueOf(vVar.a.getBoolean(strA, false)));
        } catch (ClassCastException e2) {
            v.c.b("Key %s from sharedPreferences has type other than long: %s", strA, e2.getMessage());
            return new com.google.firebase.perf.util.d();
        }
    }

    public final com.google.firebase.perf.util.d b(D4 d4) {
        v vVar = this.c;
        String strA = d4.a();
        if (strA == null) {
            vVar.getClass();
            v.c.a();
            return new com.google.firebase.perf.util.d();
        }
        if (vVar.a == null) {
            vVar.c(v.a());
            if (vVar.a == null) {
                return new com.google.firebase.perf.util.d();
            }
        }
        if (!vVar.a.contains(strA)) {
            return new com.google.firebase.perf.util.d();
        }
        try {
            try {
                return new com.google.firebase.perf.util.d(Double.valueOf(Double.longBitsToDouble(vVar.a.getLong(strA, 0L))));
            } catch (ClassCastException e2) {
                v.c.b("Key %s from sharedPreferences has type other than double: %s", strA, e2.getMessage());
                return new com.google.firebase.perf.util.d();
            }
        } catch (ClassCastException unused) {
            return new com.google.firebase.perf.util.d(Double.valueOf(Float.valueOf(vVar.a.getFloat(strA, DefinitionKt.NO_Float_VALUE)).doubleValue()));
        }
    }

    public final com.google.firebase.perf.util.d c(D4 d4) {
        v vVar = this.c;
        String strA = d4.a();
        if (strA == null) {
            vVar.getClass();
            v.c.a();
            return new com.google.firebase.perf.util.d();
        }
        if (vVar.a == null) {
            vVar.c(v.a());
            if (vVar.a == null) {
                return new com.google.firebase.perf.util.d();
            }
        }
        if (!vVar.a.contains(strA)) {
            return new com.google.firebase.perf.util.d();
        }
        try {
            return new com.google.firebase.perf.util.d(Long.valueOf(vVar.a.getLong(strA, 0L)));
        } catch (ClassCastException e2) {
            v.c.b("Key %s from sharedPreferences has type other than long: %s", strA, e2.getMessage());
            return new com.google.firebase.perf.util.d();
        }
    }

    public final com.google.firebase.perf.util.d d(D4 d4) {
        v vVar = this.c;
        String strA = d4.a();
        if (strA == null) {
            vVar.getClass();
            v.c.a();
            return new com.google.firebase.perf.util.d();
        }
        if (vVar.a == null) {
            vVar.c(v.a());
            if (vVar.a == null) {
                return new com.google.firebase.perf.util.d();
            }
        }
        if (!vVar.a.contains(strA)) {
            return new com.google.firebase.perf.util.d();
        }
        try {
            return new com.google.firebase.perf.util.d(vVar.a.getString(strA, ""));
        } catch (ClassCastException e2) {
            v.c.b("Key %s from sharedPreferences has type other than String: %s", strA, e2.getMessage());
            return new com.google.firebase.perf.util.d();
        }
    }

    public final boolean f() {
        d dVarC = d.c();
        com.google.firebase.perf.util.d dVarH = h(dVarC);
        if (dVarH.b()) {
            return ((Boolean) dVarH.a()).booleanValue();
        }
        com.google.firebase.perf.util.d dVar = this.a.getBoolean("fpr_experiment_app_start_ttid");
        if (dVar.b()) {
            this.c.g("com.google.firebase.perf.ExperimentTTID", ((Boolean) dVar.a()).booleanValue());
            return ((Boolean) dVar.a()).booleanValue();
        }
        com.google.firebase.perf.util.d dVarA = a(dVarC);
        if (dVarA.b()) {
            return ((Boolean) dVarA.a()).booleanValue();
        }
        return false;
    }

    public final Boolean g() {
        b bVar;
        c cVar;
        synchronized (b.class) {
            try {
                if (b.b == null) {
                    b.b = new b();
                }
                bVar = b.b;
            } finally {
            }
        }
        com.google.firebase.perf.util.d dVarH = h(bVar);
        if ((dVarH.b() ? (Boolean) dVarH.a() : Boolean.FALSE).booleanValue()) {
            return Boolean.FALSE;
        }
        synchronized (c.class) {
            try {
                if (c.b == null) {
                    c.b = new c();
                }
                cVar = c.b;
            } finally {
            }
        }
        com.google.firebase.perf.util.d dVarA = a(cVar);
        if (dVarA.b()) {
            return (Boolean) dVarA.a();
        }
        com.google.firebase.perf.util.d dVarH2 = h(cVar);
        if (dVarH2.b()) {
            return (Boolean) dVarH2.a();
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0018  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x001e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.firebase.perf.util.d h(com.google.android.gms.internal.mlkit_vision_common.D4 r3) {
        /*
            r2 = this;
            com.google.firebase.perf.util.c r0 = r2.b
            java.lang.String r3 = r3.b()
            if (r3 == 0) goto L12
            android.os.Bundle r1 = r0.a
            boolean r1 = r1.containsKey(r3)
            if (r1 == 0) goto L15
            r1 = 1
            goto L16
        L12:
            r0.getClass()
        L15:
            r1 = 0
        L16:
            if (r1 != 0) goto L1e
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            return r3
        L1e:
            android.os.Bundle r0 = r0.a     // Catch: java.lang.ClassCastException -> L34
            java.lang.Object r0 = r0.get(r3)     // Catch: java.lang.ClassCastException -> L34
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.ClassCastException -> L34
            if (r0 != 0) goto L2e
            com.google.firebase.perf.util.d r0 = new com.google.firebase.perf.util.d     // Catch: java.lang.ClassCastException -> L34
            r0.<init>()     // Catch: java.lang.ClassCastException -> L34
            return r0
        L2e:
            com.google.firebase.perf.util.d r1 = new com.google.firebase.perf.util.d     // Catch: java.lang.ClassCastException -> L34
            r1.<init>(r0)     // Catch: java.lang.ClassCastException -> L34
            return r1
        L34:
            r0 = move-exception
            java.lang.String r0 = r0.getMessage()
            java.lang.Object[] r3 = new java.lang.Object[]{r3, r0}
            com.google.firebase.perf.logging.a r0 = com.google.firebase.perf.util.c.b
            java.lang.String r1 = "Metadata key %s contains type other than boolean: %s"
            r0.b(r1, r3)
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.config.a.h(com.google.android.gms.internal.mlkit_vision_common.D4):com.google.firebase.perf.util.d");
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0040  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.firebase.perf.util.d i(com.google.android.gms.internal.mlkit_vision_common.D4 r3) {
        /*
            r2 = this;
            com.google.firebase.perf.util.c r0 = r2.b
            java.lang.String r3 = r3.b()
            if (r3 == 0) goto L12
            android.os.Bundle r1 = r0.a
            boolean r1 = r1.containsKey(r3)
            if (r1 == 0) goto L15
            r1 = 1
            goto L16
        L12:
            r0.getClass()
        L15:
            r1 = 0
        L16:
            if (r1 != 0) goto L1e
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            return r3
        L1e:
            android.os.Bundle r0 = r0.a
            java.lang.Object r0 = r0.get(r3)
            if (r0 != 0) goto L2c
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            return r3
        L2c:
            boolean r1 = r0 instanceof java.lang.Float
            if (r1 == 0) goto L40
            java.lang.Float r0 = (java.lang.Float) r0
            double r0 = r0.doubleValue()
            java.lang.Double r3 = java.lang.Double.valueOf(r0)
            com.google.firebase.perf.util.d r0 = new com.google.firebase.perf.util.d
            r0.<init>(r3)
            return r0
        L40:
            boolean r1 = r0 instanceof java.lang.Double
            if (r1 == 0) goto L4c
            java.lang.Double r0 = (java.lang.Double) r0
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>(r0)
            return r3
        L4c:
            java.lang.Object[] r3 = new java.lang.Object[]{r3}
            com.google.firebase.perf.logging.a r0 = com.google.firebase.perf.util.c.b
            java.lang.String r1 = "Metadata key %s contains type other than double: %s"
            r0.b(r1, r3)
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.config.a.i(com.google.android.gms.internal.mlkit_vision_common.D4):com.google.firebase.perf.util.d");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0018  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x001e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v4, types: [android.os.BaseBundle, android.os.Bundle] */
    /* JADX WARN: Type inference failed for: r1v4, types: [android.os.BaseBundle, android.os.Bundle] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r3v13, types: [com.google.firebase.perf.util.d] */
    /* JADX WARN: Type inference failed for: r3v2, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v4, types: [com.google.firebase.perf.util.d] */
    /* JADX WARN: Type inference failed for: r3v5 */
    /* JADX WARN: Type inference failed for: r3v6 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Type inference failed for: r3v8, types: [com.google.firebase.perf.util.d] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.firebase.perf.util.d j(com.google.android.gms.internal.mlkit_vision_common.D4 r3) {
        /*
            r2 = this;
            com.google.firebase.perf.util.c r0 = r2.b
            java.lang.String r3 = r3.b()
            if (r3 == 0) goto L12
            android.os.Bundle r1 = r0.a
            boolean r1 = r1.containsKey(r3)
            if (r1 == 0) goto L15
            r1 = 1
            goto L16
        L12:
            r0.getClass()
        L15:
            r1 = 0
        L16:
            if (r1 != 0) goto L1e
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
            goto L4b
        L1e:
            android.os.Bundle r0 = r0.a     // Catch: java.lang.ClassCastException -> L36
            java.lang.Object r0 = r0.get(r3)     // Catch: java.lang.ClassCastException -> L36
            java.lang.Integer r0 = (java.lang.Integer) r0     // Catch: java.lang.ClassCastException -> L36
            if (r0 != 0) goto L2f
            com.google.firebase.perf.util.d r0 = new com.google.firebase.perf.util.d     // Catch: java.lang.ClassCastException -> L36
            r0.<init>()     // Catch: java.lang.ClassCastException -> L36
            r3 = r0
            goto L4b
        L2f:
            com.google.firebase.perf.util.d r1 = new com.google.firebase.perf.util.d     // Catch: java.lang.ClassCastException -> L36
            r1.<init>(r0)     // Catch: java.lang.ClassCastException -> L36
            r3 = r1
            goto L4b
        L36:
            r0 = move-exception
            java.lang.String r0 = r0.getMessage()
            java.lang.Object[] r3 = new java.lang.Object[]{r3, r0}
            com.google.firebase.perf.logging.a r0 = com.google.firebase.perf.util.c.b
            java.lang.String r1 = "Metadata key %s contains type other than int: %s"
            r0.b(r1, r3)
            com.google.firebase.perf.util.d r3 = new com.google.firebase.perf.util.d
            r3.<init>()
        L4b:
            boolean r0 = r3.b()
            if (r0 == 0) goto L66
            java.lang.Object r3 = r3.a()
            java.lang.Integer r3 = (java.lang.Integer) r3
            int r3 = r3.intValue()
            long r0 = (long) r3
            java.lang.Long r3 = java.lang.Long.valueOf(r0)
            com.google.firebase.perf.util.d r0 = new com.google.firebase.perf.util.d
            r0.<init>(r3)
            goto L6b
        L66:
            com.google.firebase.perf.util.d r0 = new com.google.firebase.perf.util.d
            r0.<init>()
        L6b:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.config.a.j(com.google.android.gms.internal.mlkit_vision_common.D4):com.google.firebase.perf.util.d");
    }

    public final long k() {
        j jVar;
        synchronized (j.class) {
            try {
                if (j.b == null) {
                    j.b = new j();
                }
                jVar = j.b;
            } catch (Throwable th) {
                throw th;
            }
        }
        RemoteConfigManager remoteConfigManager = this.a;
        jVar.getClass();
        com.google.firebase.perf.util.d dVar = remoteConfigManager.getLong("fpr_rl_time_limit_sec");
        if (dVar.b() && ((Long) dVar.a()).longValue() > 0) {
            this.c.d(((Long) dVar.a()).longValue(), "com.google.firebase.perf.TimeLimitSec");
            return ((Long) dVar.a()).longValue();
        }
        com.google.firebase.perf.util.d dVarC = c(jVar);
        if (!dVarC.b() || ((Long) dVarC.a()).longValue() <= 0) {
            return 600L;
        }
        return ((Long) dVarC.a()).longValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x00dc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean o() {
        /*
            r6 = this;
            java.lang.Boolean r0 = r6.g()
            r1 = 0
            r2 = 1
            if (r0 == 0) goto Le
            boolean r0 = r0.booleanValue()
            if (r0 != r2) goto Le0
        Le:
            java.lang.Class<com.google.firebase.perf.config.l> r0 = com.google.firebase.perf.config.l.class
            monitor-enter(r0)
            com.google.firebase.perf.config.l r3 = com.google.firebase.perf.config.l.b     // Catch: java.lang.Throwable -> L1d
            if (r3 != 0) goto L20
            com.google.firebase.perf.config.l r3 = new com.google.firebase.perf.config.l     // Catch: java.lang.Throwable -> L1d
            r3.<init>()     // Catch: java.lang.Throwable -> L1d
            com.google.firebase.perf.config.l.b = r3     // Catch: java.lang.Throwable -> L1d
            goto L20
        L1d:
            r1 = move-exception
            goto Le1
        L20:
            com.google.firebase.perf.config.l r3 = com.google.firebase.perf.config.l.b     // Catch: java.lang.Throwable -> L1d
            monitor-exit(r0)
            com.google.firebase.perf.util.d r0 = r6.a(r3)
            com.google.firebase.perf.config.RemoteConfigManager r3 = r6.a
            java.lang.String r4 = "fpr_enabled"
            com.google.firebase.perf.util.d r3 = r3.getBoolean(r4)
            boolean r4 = r3.b()
            if (r4 == 0) goto L61
            com.google.firebase.perf.config.RemoteConfigManager r4 = r6.a
            boolean r4 = r4.isLastFetchFailed()
            if (r4 == 0) goto L3f
            r0 = r1
            goto L73
        L3f:
            java.lang.Object r3 = r3.a()
            java.lang.Boolean r3 = (java.lang.Boolean) r3
            boolean r4 = r0.b()
            if (r4 == 0) goto L51
            java.lang.Object r0 = r0.a()
            if (r0 == r3) goto L5c
        L51:
            com.google.firebase.perf.config.v r0 = r6.c
            java.lang.String r4 = "com.google.firebase.perf.SdkEnabled"
            boolean r5 = r3.booleanValue()
            r0.g(r4, r5)
        L5c:
            boolean r0 = r3.booleanValue()
            goto L73
        L61:
            boolean r3 = r0.b()
            if (r3 == 0) goto L72
            java.lang.Object r0 = r0.a()
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            goto L73
        L72:
            r0 = r2
        L73:
            if (r0 == 0) goto Ldc
            java.lang.Class<com.google.firebase.perf.config.k> r0 = com.google.firebase.perf.config.k.class
            monitor-enter(r0)
            com.google.firebase.perf.config.k r3 = com.google.firebase.perf.config.k.b     // Catch: java.lang.Throwable -> L84
            if (r3 != 0) goto L86
            com.google.firebase.perf.config.k r3 = new com.google.firebase.perf.config.k     // Catch: java.lang.Throwable -> L84
            r3.<init>()     // Catch: java.lang.Throwable -> L84
            com.google.firebase.perf.config.k.b = r3     // Catch: java.lang.Throwable -> L84
            goto L86
        L84:
            r1 = move-exception
            goto Lda
        L86:
            com.google.firebase.perf.config.k r3 = com.google.firebase.perf.config.k.b     // Catch: java.lang.Throwable -> L84
            monitor-exit(r0)
            com.google.firebase.perf.util.d r0 = r6.d(r3)
            com.google.firebase.perf.config.RemoteConfigManager r3 = r6.a
            java.lang.String r4 = "fpr_disabled_android_versions"
            com.google.firebase.perf.util.d r3 = r3.getString(r4)
            boolean r4 = r3.b()
            if (r4 == 0) goto Lbf
            java.lang.Object r3 = r3.a()
            java.lang.String r3 = (java.lang.String) r3
            boolean r4 = r0.b()
            if (r4 == 0) goto Lb3
            java.lang.Object r0 = r0.a()
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = r0.equals(r3)
            if (r0 != 0) goto Lba
        Lb3:
            com.google.firebase.perf.config.v r0 = r6.c
            java.lang.String r4 = "com.google.firebase.perf.SdkDisabledVersions"
            r0.f(r4, r3)
        Lba:
            boolean r0 = m(r3)
            goto Ld6
        Lbf:
            boolean r3 = r0.b()
            if (r3 == 0) goto Ld0
            java.lang.Object r0 = r0.a()
            java.lang.String r0 = (java.lang.String) r0
            boolean r0 = m(r0)
            goto Ld6
        Ld0:
            java.lang.String r0 = ""
            boolean r0 = m(r0)
        Ld6:
            if (r0 != 0) goto Ldc
            r0 = r2
            goto Ldd
        Lda:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L84
            throw r1
        Ldc:
            r0 = r1
        Ldd:
            if (r0 == 0) goto Le0
            return r2
        Le0:
            return r1
        Le1:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L1d
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.config.a.o():boolean");
    }
}
