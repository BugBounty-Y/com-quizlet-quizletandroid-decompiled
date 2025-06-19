package com.google.firebase.remoteconfig;

import android.app.Application;
import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.api.internal.ComponentCallbacks2C1645c;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.firebase.h;
import com.google.firebase.remoteconfig.internal.ConfigFetchHttpClient;
import com.google.firebase.remoteconfig.internal.j;
import com.google.firebase.remoteconfig.internal.k;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class f implements com.google.firebase.remoteconfig.interop.a {
    public static final Random j = new Random();
    public static final HashMap k = new HashMap();
    public final Context b;
    public final ScheduledExecutorService c;
    public final h d;
    public final com.google.firebase.installations.d e;
    public final com.google.firebase.abt.b f;
    public final com.google.firebase.inject.b g;
    public final String h;
    public final HashMap a = new HashMap();
    public final HashMap i = new HashMap();

    public f(Context context, ScheduledExecutorService scheduledExecutorService, h hVar, com.google.firebase.installations.d dVar, com.google.firebase.abt.b bVar, com.google.firebase.inject.b bVar2) {
        this.b = context;
        this.c = scheduledExecutorService;
        this.d = hVar;
        this.e = dVar;
        this.f = bVar;
        this.g = bVar2;
        hVar.a();
        this.h = hVar.c.b;
        AtomicReference atomicReference = e.a;
        Application application = (Application) context.getApplicationContext();
        AtomicReference atomicReference2 = e.a;
        if (atomicReference2.get() == null) {
            e eVar = new e();
            while (true) {
                if (atomicReference2.compareAndSet(null, eVar)) {
                    ComponentCallbacks2C1645c.b(application);
                    ComponentCallbacks2C1645c.e.a(eVar);
                    break;
                } else if (atomicReference2.get() != null) {
                    break;
                }
            }
        }
        S3.g(scheduledExecutorService, new androidx.work.impl.utils.d(this, 6));
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0028 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized com.google.firebase.remoteconfig.b a(com.google.firebase.h r13, java.lang.String r14, com.google.firebase.installations.d r15, com.google.firebase.abt.b r16, java.util.concurrent.Executor r17, com.google.firebase.remoteconfig.internal.b r18, com.google.firebase.remoteconfig.internal.b r19, com.google.firebase.remoteconfig.internal.b r20, com.google.firebase.remoteconfig.internal.e r21, com.google.firebase.remoteconfig.internal.f r22, com.google.firebase.remoteconfig.internal.j r23, com.quizlet.data.repository.explanations.question.a r24) {
        /*
            r12 = this;
            monitor-enter(r12)
            java.util.HashMap r0 = r12.a     // Catch: java.lang.Throwable -> L61
            boolean r0 = r0.containsKey(r14)     // Catch: java.lang.Throwable -> L61
            if (r0 != 0) goto L68
            com.google.firebase.remoteconfig.b r1 = new com.google.firebase.remoteconfig.b     // Catch: java.lang.Throwable -> L61
            java.lang.String r0 = "firebase"
            boolean r0 = r14.equals(r0)     // Catch: java.lang.Throwable -> L61
            if (r0 == 0) goto L23
            r13.a()     // Catch: java.lang.Throwable -> L61
            java.lang.String r0 = "[DEFAULT]"
            java.lang.String r2 = r13.b     // Catch: java.lang.Throwable -> L61
            boolean r0 = r2.equals(r0)     // Catch: java.lang.Throwable -> L61
            if (r0 == 0) goto L23
            r2 = r16
            goto L25
        L23:
            r0 = 0
            r2 = r0
        L25:
            android.content.Context r8 = r12.b     // Catch: java.lang.Throwable -> L61
            monitor-enter(r12)     // Catch: java.lang.Throwable -> L61
            com.quizlet.data.repository.classfolder.e r3 = new com.quizlet.data.repository.classfolder.e     // Catch: java.lang.Throwable -> L64
            java.util.concurrent.ScheduledExecutorService r11 = r12.c     // Catch: java.lang.Throwable -> L64
            r4 = r13
            r9 = r14
            r5 = r15
            r7 = r19
            r6 = r21
            r10 = r23
            r3.<init>(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L64
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L61
            r4 = r18
            r5 = r19
            r6 = r20
            r7 = r21
            r8 = r22
            r9 = r23
            r11 = r24
            r10 = r3
            r3 = r17
            r1.<init>(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L61
            r19.b()     // Catch: java.lang.Throwable -> L61
            r20.b()     // Catch: java.lang.Throwable -> L61
            r18.b()     // Catch: java.lang.Throwable -> L61
            java.util.HashMap r0 = r12.a     // Catch: java.lang.Throwable -> L61
            r0.put(r14, r1)     // Catch: java.lang.Throwable -> L61
            java.util.HashMap r0 = com.google.firebase.remoteconfig.f.k     // Catch: java.lang.Throwable -> L61
            r0.put(r14, r1)     // Catch: java.lang.Throwable -> L61
            goto L68
        L61:
            r0 = move-exception
            r13 = r0
            goto L72
        L64:
            r0 = move-exception
            r13 = r0
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L64
            throw r13     // Catch: java.lang.Throwable -> L61
        L68:
            java.util.HashMap r0 = r12.a     // Catch: java.lang.Throwable -> L61
            java.lang.Object r13 = r0.get(r14)     // Catch: java.lang.Throwable -> L61
            com.google.firebase.remoteconfig.b r13 = (com.google.firebase.remoteconfig.b) r13     // Catch: java.lang.Throwable -> L61
            monitor-exit(r12)
            return r13
        L72:
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L61
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.remoteconfig.f.a(com.google.firebase.h, java.lang.String, com.google.firebase.installations.d, com.google.firebase.abt.b, java.util.concurrent.Executor, com.google.firebase.remoteconfig.internal.b, com.google.firebase.remoteconfig.internal.b, com.google.firebase.remoteconfig.internal.b, com.google.firebase.remoteconfig.internal.e, com.google.firebase.remoteconfig.internal.f, com.google.firebase.remoteconfig.internal.j, com.quizlet.data.repository.explanations.question.a):com.google.firebase.remoteconfig.b");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0062  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized com.google.firebase.remoteconfig.b b(java.lang.String r15) throws java.lang.Throwable {
        /*
            r14 = this;
            monitor-enter(r14)
            java.lang.String r0 = "fetch"
            com.google.firebase.remoteconfig.internal.b r7 = r14.c(r15, r0)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = "activate"
            com.google.firebase.remoteconfig.internal.b r8 = r14.c(r15, r0)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = "defaults"
            com.google.firebase.remoteconfig.internal.b r9 = r14.c(r15, r0)     // Catch: java.lang.Throwable -> Lb5
            android.content.Context r0 = r14.b     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r1 = r14.h     // Catch: java.lang.Throwable -> Lb5
            java.lang.StringBuilder r2 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r3 = "frc_"
            r2.<init>(r3)     // Catch: java.lang.Throwable -> Lb5
            r2.append(r1)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r1 = "_"
            r2.append(r1)     // Catch: java.lang.Throwable -> Lb5
            r2.append(r15)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r1 = "_settings"
            r2.append(r1)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r1 = r2.toString()     // Catch: java.lang.Throwable -> Lb5
            r2 = 0
            android.content.SharedPreferences r0 = r0.getSharedPreferences(r1, r2)     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.remoteconfig.internal.j r12 = new com.google.firebase.remoteconfig.internal.j     // Catch: java.lang.Throwable -> Lb5
            r12.<init>(r0)     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.remoteconfig.internal.f r11 = new com.google.firebase.remoteconfig.internal.f     // Catch: java.lang.Throwable -> Lb5
            java.util.concurrent.ScheduledExecutorService r0 = r14.c     // Catch: java.lang.Throwable -> Lb5
            r11.<init>(r0, r8, r9)     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.h r0 = r14.d     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.inject.b r1 = r14.g     // Catch: java.lang.Throwable -> Lb5
            r0.a()     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r2 = "[DEFAULT]"
            java.lang.String r0 = r0.b     // Catch: java.lang.Throwable -> Lb5
            boolean r0 = r0.equals(r2)     // Catch: java.lang.Throwable -> Lb5
            if (r0 == 0) goto L62
            java.lang.String r0 = "firebase"
            boolean r0 = r15.equals(r0)     // Catch: java.lang.Throwable -> L7a
            if (r0 == 0) goto L62
            androidx.work.impl.model.e r0 = new androidx.work.impl.model.e     // Catch: java.lang.Throwable -> L7a
            r0.<init>(r1)     // Catch: java.lang.Throwable -> L7a
            goto L63
        L62:
            r0 = 0
        L63:
            if (r0 == 0) goto L7d
            com.google.firebase.remoteconfig.d r1 = new com.google.firebase.remoteconfig.d     // Catch: java.lang.Throwable -> L7a
            r1.<init>(r0)     // Catch: java.lang.Throwable -> L7a
            java.util.HashSet r2 = r11.a     // Catch: java.lang.Throwable -> L7a
            monitor-enter(r2)     // Catch: java.lang.Throwable -> L7a
            java.util.HashSet r0 = r11.a     // Catch: java.lang.Throwable -> L74
            r0.add(r1)     // Catch: java.lang.Throwable -> L74
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L74
            goto L7d
        L74:
            r0 = move-exception
            r15 = r0
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L74
            throw r15     // Catch: java.lang.Throwable -> L7a
        L78:
            r1 = r14
            goto Lb8
        L7a:
            r0 = move-exception
            r15 = r0
            goto L78
        L7d:
            androidx.work.impl.model.l r0 = new androidx.work.impl.model.l     // Catch: java.lang.Throwable -> Lb5
            r1 = 13
            r0.<init>(r1)     // Catch: java.lang.Throwable -> Lb5
            r0.b = r8     // Catch: java.lang.Throwable -> Lb5
            r0.c = r9     // Catch: java.lang.Throwable -> Lb5
            com.quizlet.data.repository.explanations.question.a r13 = new com.quizlet.data.repository.explanations.question.a     // Catch: java.lang.Throwable -> Lb5
            r13.<init>()     // Catch: java.lang.Throwable -> Lb5
            java.util.concurrent.ConcurrentHashMap r1 = new java.util.concurrent.ConcurrentHashMap     // Catch: java.lang.Throwable -> Lb5
            r1.<init>()     // Catch: java.lang.Throwable -> Lb5
            java.util.Set r1 = java.util.Collections.newSetFromMap(r1)     // Catch: java.lang.Throwable -> Lb5
            r13.d = r1     // Catch: java.lang.Throwable -> Lb5
            r13.a = r8     // Catch: java.lang.Throwable -> Lb5
            r13.b = r0     // Catch: java.lang.Throwable -> Lb5
            java.util.concurrent.ScheduledExecutorService r6 = r14.c     // Catch: java.lang.Throwable -> Lb5
            r13.c = r6     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.h r2 = r14.d     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.installations.d r4 = r14.e     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.abt.b r5 = r14.f     // Catch: java.lang.Throwable -> Lb5
            com.google.firebase.remoteconfig.internal.e r10 = r14.d(r15, r7, r12)     // Catch: java.lang.Throwable -> Lb5
            r1 = r14
            r3 = r15
            com.google.firebase.remoteconfig.b r15 = r1.a(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13)     // Catch: java.lang.Throwable -> Lb2
            monitor-exit(r14)
            return r15
        Lb2:
            r0 = move-exception
        Lb3:
            r15 = r0
            goto Lb8
        Lb5:
            r0 = move-exception
            r1 = r14
            goto Lb3
        Lb8:
            monitor-exit(r14)     // Catch: java.lang.Throwable -> Lb2
            throw r15
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.remoteconfig.f.b(java.lang.String):com.google.firebase.remoteconfig.b");
    }

    public final com.google.firebase.remoteconfig.internal.b c(String str, String str2) {
        k kVar;
        com.google.firebase.remoteconfig.internal.b bVar;
        String strT = android.support.v4.media.session.a.t(AbstractC0147y.h("frc_", this.h, "_", str, "_"), str2, ".json");
        ScheduledExecutorService scheduledExecutorService = this.c;
        Context context = this.b;
        HashMap map = k.c;
        synchronized (k.class) {
            try {
                HashMap map2 = k.c;
                if (!map2.containsKey(strT)) {
                    map2.put(strT, new k(context, strT));
                }
                kVar = (k) map2.get(strT);
            } finally {
            }
        }
        HashMap map3 = com.google.firebase.remoteconfig.internal.b.d;
        synchronized (com.google.firebase.remoteconfig.internal.b.class) {
            try {
                String str3 = kVar.b;
                HashMap map4 = com.google.firebase.remoteconfig.internal.b.d;
                if (!map4.containsKey(str3)) {
                    map4.put(str3, new com.google.firebase.remoteconfig.internal.b(scheduledExecutorService, kVar));
                }
                bVar = (com.google.firebase.remoteconfig.internal.b) map4.get(str3);
            } finally {
            }
        }
        return bVar;
    }

    public final synchronized com.google.firebase.remoteconfig.internal.e d(String str, com.google.firebase.remoteconfig.internal.b bVar, j jVar) {
        com.google.firebase.installations.d dVar;
        com.google.firebase.inject.b fVar;
        ScheduledExecutorService scheduledExecutorService;
        Random random;
        String str2;
        h hVar;
        try {
            dVar = this.e;
            h hVar2 = this.d;
            hVar2.a();
            fVar = hVar2.b.equals("[DEFAULT]") ? this.g : new com.google.firebase.components.f(11);
            scheduledExecutorService = this.c;
            random = j;
            h hVar3 = this.d;
            hVar3.a();
            str2 = hVar3.c.a;
            hVar = this.d;
            hVar.a();
        } catch (Throwable th) {
            throw th;
        }
        return new com.google.firebase.remoteconfig.internal.e(dVar, fVar, scheduledExecutorService, random, bVar, new ConfigFetchHttpClient(this.b, hVar.c.b, str2, str, jVar.a.getLong("fetch_timeout_in_seconds", 60L), jVar.a.getLong("fetch_timeout_in_seconds", 60L)), jVar, this.i);
    }
}
