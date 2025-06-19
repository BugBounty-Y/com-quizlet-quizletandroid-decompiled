package com.google.android.gms.measurement.internal;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.zzdj;
import com.google.android.gms.internal.mlkit_vision_common.A4;
import java.util.ArrayDeque;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C0 implements Application.ActivityLifecycleCallbacks {
    public final /* synthetic */ int a;
    public final Object b;

    public C0(D0 d0) {
        this.a = 0;
        this.b = d0;
    }

    private final void a(Activity activity) {
    }

    private final void b(Activity activity) {
    }

    private final void c(Activity activity) {
    }

    private final void d(Activity activity, Bundle bundle) {
    }

    private final void e(Activity activity) {
    }

    private final void f(Activity activity) {
    }

    private final void g(Activity activity) {
    }

    private final void h(Activity activity) {
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0049 A[Catch: all -> 0x0028, RuntimeException -> 0x002b, TryCatch #1 {RuntimeException -> 0x002b, blocks: (B:3:0x0009, B:5:0x0019, B:7:0x001f, B:22:0x0049, B:25:0x0050, B:27:0x0063, B:29:0x006b, B:35:0x007b, B:40:0x0088, B:15:0x002e, B:17:0x0035, B:19:0x0041), top: B:49:0x0009, outer: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0086  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void i(com.google.android.gms.internal.measurement.zzdj r9, android.os.Bundle r10) {
        /*
            r8 = this;
            java.lang.Object r0 = r8.b
            com.google.android.gms.measurement.internal.D0 r0 = (com.google.android.gms.measurement.internal.D0) r0
            java.lang.Object r0 = r0.b
            r1 = r0
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.measurement.internal.I r0 = r1.i     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            com.google.android.gms.measurement.internal.Y.k(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            com.google.android.gms.internal.ads.Ka r0 = r0.o     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            java.lang.String r2 = "onActivityCreated"
            r0.f(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            android.content.Intent r0 = r9.c     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r0 == 0) goto L97
            android.net.Uri r2 = r0.getData()     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r2 == 0) goto L2e
            boolean r3 = r2.isHierarchical()     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r3 != 0) goto L26
            goto L2e
        L26:
            r5 = r2
            goto L47
        L28:
            r0 = move-exception
            goto Lb5
        L2b:
            r0 = move-exception
            goto La0
        L2e:
            android.os.Bundle r2 = r0.getExtras()     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            r3 = 0
            if (r2 == 0) goto L46
            java.lang.String r4 = "com.android.vending.referral_url"
            java.lang.String r2 = r2.getString(r4)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            boolean r4 = android.text.TextUtils.isEmpty(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r4 != 0) goto L46
            android.net.Uri r2 = android.net.Uri.parse(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            goto L26
        L46:
            r5 = r3
        L47:
            if (r5 == 0) goto L97
            boolean r2 = r5.isHierarchical()     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r2 != 0) goto L50
            goto L97
        L50:
            com.google.android.gms.measurement.internal.x1 r2 = r1.l     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            com.google.android.gms.measurement.internal.Y.h(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            java.lang.String r2 = "android.intent.extra.REFERRER_NAME"
            java.lang.String r0 = r0.getStringExtra(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            java.lang.String r2 = "android-app://com.google.android.googlequicksearchbox/https/www.google.com"
            boolean r2 = r2.equals(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r2 != 0) goto L78
            java.lang.String r2 = "https://www.google.com"
            boolean r2 = r2.equals(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r2 != 0) goto L78
            java.lang.String r2 = "android-app://com.google.appcrawler"
            boolean r0 = r2.equals(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r0 == 0) goto L74
            goto L78
        L74:
            java.lang.String r0 = "auto"
        L76:
            r6 = r0
            goto L7b
        L78:
            java.lang.String r0 = "gs"
            goto L76
        L7b:
            java.lang.String r0 = "referrer"
            java.lang.String r7 = r5.getQueryParameter(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            if (r10 != 0) goto L86
            r0 = 1
        L84:
            r4 = r0
            goto L88
        L86:
            r0 = 0
            goto L84
        L88:
            com.google.android.gms.measurement.internal.X r0 = r1.j     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            com.google.android.gms.measurement.internal.Y.k(r0)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            com.google.android.gms.measurement.internal.z0 r2 = new com.google.android.gms.measurement.internal.z0     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            r3 = r8
            r2.<init>(r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            r0.c0(r2)     // Catch: java.lang.Throwable -> L28 java.lang.RuntimeException -> L2b
            goto Lac
        L97:
            com.google.android.gms.measurement.internal.O0 r0 = r1.o
            com.google.android.gms.measurement.internal.Y.j(r0)
            r0.a0(r9, r10)
            return
        La0:
            com.google.android.gms.measurement.internal.I r2 = r1.i     // Catch: java.lang.Throwable -> L28
            com.google.android.gms.measurement.internal.Y.k(r2)     // Catch: java.lang.Throwable -> L28
            com.google.android.gms.internal.ads.Ka r2 = r2.g     // Catch: java.lang.Throwable -> L28
            java.lang.String r3 = "Throwable caught in onActivityCreated"
            r2.g(r3, r0)     // Catch: java.lang.Throwable -> L28
        Lac:
            com.google.android.gms.measurement.internal.O0 r0 = r1.o
            com.google.android.gms.measurement.internal.Y.j(r0)
            r0.a0(r9, r10)
            return
        Lb5:
            com.google.android.gms.measurement.internal.O0 r1 = r1.o
            com.google.android.gms.measurement.internal.Y.j(r1)
            r1.a0(r9, r10)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C0.i(com.google.android.gms.internal.measurement.zzdj, android.os.Bundle):void");
    }

    public void j(zzdj zzdjVar) {
        O0 o0 = ((Y) ((D0) this.b).b).o;
        Y.j(o0);
        synchronized (o0.m) {
            try {
                if (Objects.equals(o0.h, zzdjVar)) {
                    o0.h = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (((Y) o0.b).g.g0()) {
            o0.g.remove(Integer.valueOf(zzdjVar.a));
        }
    }

    public void k(zzdj zzdjVar) {
        Y y = (Y) ((D0) this.b).b;
        O0 o0 = y.o;
        Y.j(o0);
        synchronized (o0.m) {
            o0.l = false;
            o0.i = true;
        }
        Y y2 = (Y) o0.b;
        y2.n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        if (y2.g.g0()) {
            L0 l0B0 = o0.b0(zzdjVar);
            o0.e = o0.d;
            o0.d = null;
            X x = y2.j;
            Y.k(x);
            x.c0(new com.android.volley.i(o0, l0B0, jElapsedRealtime, 5));
        } else {
            o0.d = null;
            X x2 = y2.j;
            Y.k(x2);
            x2.c0(new com.google.ads.conversiontracking.i(o0, jElapsedRealtime, 2));
        }
        g1 g1Var = y.k;
        Y.j(g1Var);
        Y y3 = (Y) g1Var.b;
        y3.n.getClass();
        long jElapsedRealtime2 = SystemClock.elapsedRealtime();
        X x3 = y3.j;
        Y.k(x3);
        x3.c0(new d1(g1Var, jElapsedRealtime2, 1));
    }

    public void l(zzdj zzdjVar) {
        Y y = (Y) ((D0) this.b).b;
        g1 g1Var = y.k;
        Y.j(g1Var);
        Y y2 = (Y) g1Var.b;
        y2.n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        X x = y2.j;
        Y.k(x);
        x.c0(new d1(g1Var, jElapsedRealtime, 0));
        O0 o0 = y.o;
        Y.j(o0);
        Object obj = o0.m;
        synchronized (obj) {
            o0.l = true;
            if (!Objects.equals(zzdjVar, o0.h)) {
                synchronized (obj) {
                    o0.h = zzdjVar;
                    o0.i = false;
                    Y y3 = (Y) o0.b;
                    if (y3.g.g0()) {
                        o0.j = null;
                        X x2 = y3.j;
                        Y.k(x2);
                        x2.c0(new N0(o0, 1));
                    }
                }
            }
        }
        Y y4 = (Y) o0.b;
        if (!y4.g.g0()) {
            o0.d = o0.j;
            X x3 = y4.j;
            Y.k(x3);
            x3.c0(new N0(o0, 0));
            return;
        }
        o0.V(zzdjVar.b, o0.b0(zzdjVar), false);
        C3884o c3884o = ((Y) o0.b).q;
        Y.g(c3884o);
        Y y5 = (Y) c3884o.b;
        y5.n.getClass();
        long jElapsedRealtime2 = SystemClock.elapsedRealtime();
        X x4 = y5.j;
        Y.k(x4);
        x4.c0(new com.google.ads.conversiontracking.i(c3884o, jElapsedRealtime2, 1));
    }

    public void m(zzdj zzdjVar, Bundle bundle) {
        L0 l0;
        O0 o0 = ((Y) ((D0) this.b).b).o;
        Y.j(o0);
        if (!((Y) o0.b).g.g0() || bundle == null || (l0 = (L0) o0.g.get(Integer.valueOf(zzdjVar.a))) == null) {
            return;
        }
        Bundle bundle2 = new Bundle();
        bundle2.putLong("id", l0.c);
        bundle2.putString("name", l0.a);
        bundle2.putString("referrer_name", l0.b);
        bundle.putBundle("com.google.app_measurement.screen_service", bundle2);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        switch (this.a) {
            case 0:
                i(zzdj.a(activity), bundle);
                break;
            case 1:
                Intent intent = activity.getIntent();
                if (intent != null) {
                    Bundle bundle2 = null;
                    try {
                        Bundle extras = intent.getExtras();
                        if (extras != null) {
                            String string = extras.getString("google.message_id");
                            if (string == null) {
                                string = extras.getString("message_id");
                            }
                            if (!TextUtils.isEmpty(string)) {
                                ArrayDeque arrayDeque = (ArrayDeque) this.b;
                                if (arrayDeque.contains(string)) {
                                    break;
                                } else {
                                    arrayDeque.add(string);
                                }
                            }
                            bundle2 = extras.getBundle("gcm.n.analytics_data");
                        }
                    } catch (RuntimeException e) {
                        Log.w("FirebaseMessaging", "Failed trying to get analytics data from Intent extras.", e);
                    }
                    if (bundle2 == null ? false : "1".equals(bundle2.getString("google.c.a.e"))) {
                        if (bundle2 != null) {
                            if ("1".equals(bundle2.getString("google.c.a.tc"))) {
                                com.google.firebase.analytics.connector.b bVar = (com.google.firebase.analytics.connector.b) com.google.firebase.h.c().b(com.google.firebase.analytics.connector.b.class);
                                Log.isLoggable("FirebaseMessaging", 3);
                                if (bVar != null) {
                                    String string2 = bundle2.getString("google.c.a.c_id");
                                    com.google.firebase.analytics.connector.c cVar = (com.google.firebase.analytics.connector.c) bVar;
                                    if (com.google.firebase.analytics.connector.internal.a.c("fcm") && com.google.firebase.analytics.connector.internal.a.d("fcm", "_ln")) {
                                        C3008j0 c3008j0 = (C3008j0) cVar.a.a;
                                        c3008j0.getClass();
                                        c3008j0.c(new com.google.android.gms.internal.measurement.U(c3008j0, "fcm", "_ln", string2, 0));
                                    }
                                    Bundle bundle3 = new Bundle();
                                    bundle3.putString("source", "Firebase");
                                    bundle3.putString("medium", "notification");
                                    bundle3.putString("campaign", string2);
                                    cVar.a("fcm", "_cmp", bundle3);
                                } else {
                                    Log.w("FirebaseMessaging", "Unable to set user property for conversion tracking:  analytics library is missing");
                                }
                            } else {
                                Log.isLoggable("FirebaseMessaging", 3);
                            }
                        }
                        A4.d(bundle2, "_no");
                        break;
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) this.b)).a(activity);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        switch (this.a) {
            case 0:
                j(zzdj.a(activity));
                break;
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        switch (this.a) {
            case 0:
                k(zzdj.a(activity));
                break;
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        switch (this.a) {
            case 0:
                l(zzdj.a(activity));
                break;
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle p1) {
        switch (this.a) {
            case 0:
                m(zzdj.a(activity), p1);
                break;
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                Intrinsics.checkNotNullParameter(p1, "p1");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        switch (this.a) {
            case 0:
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        switch (this.a) {
            case 0:
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(activity, "activity");
                break;
        }
    }

    public C0(com.quizlet.usecase.b onActivityCreated) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(onActivityCreated, "onActivityCreated");
        this.b = onActivityCreated;
    }

    public C0() {
        this.a = 1;
        this.b = new ArrayDeque(10);
    }
}
