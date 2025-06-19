package com.google.android.gms.common.api;

import android.content.Context;
import android.os.Build;
import android.os.Looper;
import androidx.collection.C0209g;
import androidx.credentials.playservices.HiddenActivity;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.internal.C1643a;
import com.google.android.gms.common.api.internal.C1647e;
import com.google.android.gms.common.api.internal.G;
import com.google.android.gms.common.api.internal.p;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.Ls;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public abstract class e {
    public final Context a;
    public final String b;
    public final com.google.firebase.platforminfo.c c;
    public final com.quizlet.data.repository.activitycenter.b d;
    public final b e;
    public final C1643a f;
    public final Looper g;
    public final int h;
    public final p i;
    public final com.google.mlkit.common.sdkinternal.model.a j;
    public final C1647e k;

    public e(Context context, HiddenActivity hiddenActivity, com.quizlet.data.repository.activitycenter.b bVar, b bVar2, d dVar) {
        G g;
        u.i(context, "Null context is not permitted.");
        u.i(bVar, "Api must not be null.");
        u.i(dVar, "Settings must not be null; use Settings.DEFAULT_SETTINGS instead.");
        Context applicationContext = context.getApplicationContext();
        u.i(applicationContext, "The provided context did not have an application context.");
        this.a = applicationContext;
        int i = Build.VERSION.SDK_INT;
        String strA = (i < 30 || i < 30) ? null : androidx.core.content.b.a(context);
        this.b = strA;
        this.c = i >= 31 ? new com.google.firebase.platforminfo.c(context.getAttributionSource()) : null;
        this.d = bVar;
        this.e = bVar2;
        this.g = dVar.b;
        C1643a c1643a = new C1643a(bVar, bVar2, strA);
        this.f = c1643a;
        this.i = new p(this);
        C1647e c1647eD = C1647e.d(applicationContext);
        this.k = c1647eD;
        this.h = c1647eD.h.getAndIncrement();
        this.j = dVar.a;
        if (hiddenActivity != null && Looper.myLooper() == Looper.getMainLooper()) {
            WeakHashMap weakHashMap = G.b;
            WeakReference weakReference = (WeakReference) weakHashMap.get(hiddenActivity);
            if (weakReference == null || (g = (G) weakReference.get()) == null) {
                try {
                    g = (G) hiddenActivity.getFragmentManager().findFragmentByTag("LifecycleFragmentImpl");
                    if (g == null || g.isRemoving()) {
                        g = new G();
                        hiddenActivity.getFragmentManager().beginTransaction().add(g, "LifecycleFragmentImpl").commitAllowingStateLoss();
                    }
                    weakHashMap.put(hiddenActivity, new WeakReference(g));
                } catch (ClassCastException e) {
                    throw new IllegalStateException("Fragment with tag LifecycleFragmentImpl is not a LifecycleFragmentImpl", e);
                }
            }
            com.google.android.gms.common.api.internal.l lVarB = g.b();
            lVarB = lVarB == null ? new com.google.android.gms.common.api.internal.l(g, c1647eD, GoogleApiAvailability.d) : lVarB;
            lVarB.f.add(c1643a);
            c1647eD.e(lVarB);
        }
        Ls ls = c1647eD.n;
        ls.sendMessage(ls.obtainMessage(7, this));
    }

    public final com.quizlet.data.repository.folderwithcreator.e a() {
        com.quizlet.data.repository.folderwithcreator.e eVar = new com.quizlet.data.repository.folderwithcreator.e(6);
        Set set = Collections.EMPTY_SET;
        if (((C0209g) eVar.b) == null) {
            eVar.b = new C0209g(0);
        }
        ((C0209g) eVar.b).addAll(set);
        Context context = this.a;
        eVar.d = context.getClass().getName();
        eVar.c = context.getPackageName();
        return eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x006f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.tasks.m c(int r13, com.google.android.gms.internal.ads.AbstractC2027eu r14) {
        /*
            r12 = this;
            com.google.android.gms.tasks.f r0 = new com.google.android.gms.tasks.f
            r0.<init>()
            com.google.android.gms.common.api.internal.e r2 = r12.k
            r2.getClass()
            int r3 = r14.c
            if (r3 == 0) goto L7e
            com.google.android.gms.common.api.internal.a r4 = r12.f
            boolean r1 = r2.f()
            if (r1 != 0) goto L17
            goto L53
        L17:
            com.google.android.gms.common.internal.i r1 = com.google.android.gms.common.internal.i.a()
            java.lang.Object r1 = r1.a
            com.google.android.gms.common.internal.RootTelemetryConfiguration r1 = (com.google.android.gms.common.internal.RootTelemetryConfiguration) r1
            r5 = 1
            if (r1 == 0) goto L55
            boolean r6 = r1.b
            if (r6 == 0) goto L53
            java.util.concurrent.ConcurrentHashMap r6 = r2.j
            java.lang.Object r6 = r6.get(r4)
            com.google.android.gms.common.api.internal.n r6 = (com.google.android.gms.common.api.internal.n) r6
            if (r6 == 0) goto L50
            com.google.android.gms.common.api.c r7 = r6.b
            boolean r8 = r7 instanceof com.google.android.gms.common.internal.AbstractC1655e
            if (r8 == 0) goto L53
            com.google.android.gms.common.internal.e r7 = (com.google.android.gms.common.internal.AbstractC1655e) r7
            com.google.android.gms.common.internal.zzj r8 = r7.w
            if (r8 == 0) goto L50
            boolean r8 = r7.r()
            if (r8 != 0) goto L50
            com.google.android.gms.common.internal.ConnectionTelemetryConfiguration r1 = com.google.android.gms.common.api.internal.r.a(r6, r7, r3)
            if (r1 == 0) goto L53
            int r7 = r6.l
            int r7 = r7 + r5
            r6.l = r7
            boolean r5 = r1.c
            goto L55
        L50:
            boolean r5 = r1.c
            goto L55
        L53:
            r1 = 0
            goto L6d
        L55:
            com.google.android.gms.common.api.internal.r r1 = new com.google.android.gms.common.api.internal.r
            r6 = 0
            if (r5 == 0) goto L60
            long r8 = java.lang.System.currentTimeMillis()
            goto L61
        L60:
            r8 = r6
        L61:
            if (r5 == 0) goto L67
            long r6 = android.os.SystemClock.elapsedRealtime()
        L67:
            r10 = r8
            r7 = r6
            r5 = r10
            r1.<init>(r2, r3, r4, r5, r7)
        L6d:
            if (r1 == 0) goto L7e
            com.google.android.gms.tasks.m r3 = r0.a
            com.google.android.gms.internal.ads.Ls r4 = r2.n
            java.util.Objects.requireNonNull(r4)
            androidx.camera.core.impl.utils.executor.h r5 = new androidx.camera.core.impl.utils.executor.h
            r5.<init>(r4)
            r3.b(r5, r1)
        L7e:
            com.google.android.gms.common.api.internal.A r1 = new com.google.android.gms.common.api.internal.A
            com.google.mlkit.common.sdkinternal.model.a r3 = r12.j
            r1.<init>(r13, r14, r0, r3)
            java.util.concurrent.atomic.AtomicInteger r13 = r2.i
            com.google.android.gms.common.api.internal.u r14 = new com.google.android.gms.common.api.internal.u
            int r13 = r13.get()
            r14.<init>(r1, r13, r12)
            com.google.android.gms.internal.ads.Ls r13 = r2.n
            r1 = 4
            android.os.Message r14 = r13.obtainMessage(r1, r14)
            r13.sendMessage(r14)
            com.google.android.gms.tasks.m r13 = r0.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.e.c(int, com.google.android.gms.internal.ads.eu):com.google.android.gms.tasks.m");
    }
}
