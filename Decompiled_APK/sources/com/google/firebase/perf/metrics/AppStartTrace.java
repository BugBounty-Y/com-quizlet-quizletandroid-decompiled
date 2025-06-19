package com.google.firebase.perf.metrics;

import android.R;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.view.View;
import androidx.annotation.Keep;
import androidx.lifecycle.A;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1238a0;
import androidx.lifecycle.d0;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.h;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.transport.f;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.util.e;
import com.google.firebase.perf.v1.B;
import com.google.firebase.perf.v1.E;
import com.google.firebase.perf.v1.z;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class AppStartTrace implements Application.ActivityLifecycleCallbacks, I {
    public static final Timer v = new Timer();
    public static final long w = TimeUnit.MINUTES.toMicros(1);
    public static volatile AppStartTrace x;
    public static ThreadPoolExecutor y;
    public final f b;
    public final com.google.firebase.perf.config.a c;
    public final B d;
    public Application e;
    public final Timer g;
    public final Timer h;
    public PerfSession q;
    public boolean a = false;
    public boolean f = false;
    public Timer i = null;
    public Timer j = null;
    public Timer k = null;
    public Timer l = null;
    public Timer m = null;
    public Timer n = null;
    public Timer o = null;
    public Timer p = null;
    public boolean r = false;
    public int s = 0;
    public final b t = new b(this);
    public boolean u = false;

    public AppStartTrace(f fVar, assistantMode.utils.studiableMetadata.b bVar, com.google.firebase.perf.config.a aVar, ThreadPoolExecutor threadPoolExecutor) {
        Timer timer = null;
        this.b = fVar;
        this.c = aVar;
        y = threadPoolExecutor;
        B bP = E.P();
        bP.q("_experiment_app_start_ttid");
        this.d = bP;
        long startElapsedRealtime = Process.getStartElapsedRealtime();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        long micros = timeUnit.toMicros(startElapsedRealtime);
        long micros2 = timeUnit.toMicros(System.currentTimeMillis());
        TimeUnit timeUnit2 = TimeUnit.NANOSECONDS;
        this.g = new Timer((micros - timeUnit2.toMicros(SystemClock.elapsedRealtimeNanos())) + micros2, micros);
        com.google.firebase.a aVar2 = (com.google.firebase.a) h.c().b(com.google.firebase.a.class);
        if (aVar2 != null) {
            long micros3 = timeUnit.toMicros(aVar2.b);
            timer = new Timer((micros3 - timeUnit2.toMicros(SystemClock.elapsedRealtimeNanos())) + timeUnit.toMicros(System.currentTimeMillis()), micros3);
        }
        this.h = timer;
    }

    public static boolean c(Application application) {
        ActivityManager activityManager = (ActivityManager) application.getSystemService("activity");
        if (activityManager == null) {
            return true;
        }
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();
        if (runningAppProcesses == null) {
            return false;
        }
        String packageName = application.getPackageName();
        String strK = android.support.v4.media.session.a.k(packageName, ":");
        for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
            if (runningAppProcessInfo.importance == 100 && (runningAppProcessInfo.processName.equals(packageName) || runningAppProcessInfo.processName.startsWith(strK))) {
                return true;
            }
        }
        return false;
    }

    @Keep
    public static void setLauncherActivityOnCreateTime(String str) {
    }

    @Keep
    public static void setLauncherActivityOnResumeTime(String str) {
    }

    @Keep
    public static void setLauncherActivityOnStartTime(String str) {
    }

    public final Timer a() {
        Timer timer = this.h;
        return timer != null ? timer : v;
    }

    public final Timer b() {
        Timer timer = this.g;
        return timer != null ? timer : a();
    }

    public final void e(B b) {
        if (this.n == null || this.o == null || this.p == null) {
            return;
        }
        y.execute(new i(7, this, b));
        f();
    }

    public final synchronized void f() {
        if (this.a) {
            d0.i.f.b(this);
            this.e.unregisterActivityLifecycleCallbacks(this);
            this.a = false;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityCreated(Activity activity, Bundle bundle) {
        try {
            if (!this.r && this.i == null) {
                this.u = this.u || c(this.e);
                new WeakReference(activity);
                this.i = new Timer();
                if (b().b(this.i) > w) {
                    this.f = true;
                }
            }
        } finally {
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        View viewFindViewById;
        if (this.r || this.f || !this.c.f() || (viewFindViewById = activity.findViewById(R.id.content)) == null) {
            return;
        }
        viewFindViewById.getViewTreeObserver().removeOnDrawListener(this.t);
    }

    /* JADX WARN: Type inference failed for: r2v3, types: [com.google.firebase.perf.metrics.a] */
    /* JADX WARN: Type inference failed for: r2v5, types: [com.google.firebase.perf.metrics.a] */
    /* JADX WARN: Type inference failed for: r3v4, types: [com.google.firebase.perf.metrics.a] */
    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityResumed(Activity activity) {
        View viewFindViewById;
        try {
            if (!this.r && !this.f) {
                boolean zF = this.c.f();
                if (zF && (viewFindViewById = activity.findViewById(R.id.content)) != null) {
                    viewFindViewById.getViewTreeObserver().addOnDrawListener(this.t);
                    final int i = 0;
                    viewFindViewById.getViewTreeObserver().addOnDrawListener(new com.google.firebase.perf.util.b(viewFindViewById, new Runnable(this) { // from class: com.google.firebase.perf.metrics.a
                        public final /* synthetic */ AppStartTrace b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            AppStartTrace appStartTrace = this.b;
                            switch (i) {
                                case 0:
                                    if (appStartTrace.p == null) {
                                        appStartTrace.p = new Timer();
                                        B bP = E.P();
                                        bP.q("_experiment_onDrawFoQ");
                                        bP.o(appStartTrace.b().a);
                                        bP.p(appStartTrace.b().b(appStartTrace.p));
                                        E e = (E) bP.h();
                                        B b = appStartTrace.d;
                                        b.m(e);
                                        if (appStartTrace.g != null) {
                                            B bP2 = E.P();
                                            bP2.q("_experiment_procStart_to_classLoad");
                                            bP2.o(appStartTrace.b().a);
                                            bP2.p(appStartTrace.b().b(appStartTrace.a()));
                                            b.m((E) bP2.h());
                                        }
                                        String str = appStartTrace.u ? "true" : "false";
                                        b.k();
                                        E.A((E) b.b).put("systemDeterminedForeground", str);
                                        b.n(appStartTrace.s, "onDrawCount");
                                        z zVarA = appStartTrace.q.a();
                                        b.k();
                                        E.B((E) b.b, zVarA);
                                        appStartTrace.e(b);
                                        break;
                                    }
                                    break;
                                case 1:
                                    if (appStartTrace.n == null) {
                                        appStartTrace.n = new Timer();
                                        long j = appStartTrace.b().a;
                                        B b2 = appStartTrace.d;
                                        b2.o(j);
                                        b2.p(appStartTrace.b().b(appStartTrace.n));
                                        appStartTrace.e(b2);
                                        break;
                                    }
                                    break;
                                case 2:
                                    if (appStartTrace.o == null) {
                                        appStartTrace.o = new Timer();
                                        B bP3 = E.P();
                                        bP3.q("_experiment_preDrawFoQ");
                                        bP3.o(appStartTrace.b().a);
                                        bP3.p(appStartTrace.b().b(appStartTrace.o));
                                        E e2 = (E) bP3.h();
                                        B b3 = appStartTrace.d;
                                        b3.m(e2);
                                        appStartTrace.e(b3);
                                        break;
                                    }
                                    break;
                                default:
                                    Timer timer = AppStartTrace.v;
                                    B bP4 = E.P();
                                    bP4.q("_as");
                                    bP4.o(appStartTrace.a().a);
                                    bP4.p(appStartTrace.a().b(appStartTrace.k));
                                    ArrayList arrayList = new ArrayList(3);
                                    B bP5 = E.P();
                                    bP5.q("_astui");
                                    bP5.o(appStartTrace.a().a);
                                    bP5.p(appStartTrace.a().b(appStartTrace.i));
                                    arrayList.add((E) bP5.h());
                                    if (appStartTrace.j != null) {
                                        B bP6 = E.P();
                                        bP6.q("_astfd");
                                        bP6.o(appStartTrace.i.a);
                                        bP6.p(appStartTrace.i.b(appStartTrace.j));
                                        arrayList.add((E) bP6.h());
                                        B bP7 = E.P();
                                        bP7.q("_asti");
                                        bP7.o(appStartTrace.j.a);
                                        bP7.p(appStartTrace.j.b(appStartTrace.k));
                                        arrayList.add((E) bP7.h());
                                    }
                                    bP4.k();
                                    E.z((E) bP4.b, arrayList);
                                    z zVarA2 = appStartTrace.q.a();
                                    bP4.k();
                                    E.B((E) bP4.b, zVarA2);
                                    appStartTrace.b.c((E) bP4.h(), com.google.firebase.perf.v1.i.FOREGROUND_BACKGROUND);
                                    break;
                            }
                        }
                    }));
                    final int i2 = 1;
                    final int i3 = 2;
                    viewFindViewById.getViewTreeObserver().addOnPreDrawListener(new e(viewFindViewById, new Runnable(this) { // from class: com.google.firebase.perf.metrics.a
                        public final /* synthetic */ AppStartTrace b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            AppStartTrace appStartTrace = this.b;
                            switch (i2) {
                                case 0:
                                    if (appStartTrace.p == null) {
                                        appStartTrace.p = new Timer();
                                        B bP = E.P();
                                        bP.q("_experiment_onDrawFoQ");
                                        bP.o(appStartTrace.b().a);
                                        bP.p(appStartTrace.b().b(appStartTrace.p));
                                        E e = (E) bP.h();
                                        B b = appStartTrace.d;
                                        b.m(e);
                                        if (appStartTrace.g != null) {
                                            B bP2 = E.P();
                                            bP2.q("_experiment_procStart_to_classLoad");
                                            bP2.o(appStartTrace.b().a);
                                            bP2.p(appStartTrace.b().b(appStartTrace.a()));
                                            b.m((E) bP2.h());
                                        }
                                        String str = appStartTrace.u ? "true" : "false";
                                        b.k();
                                        E.A((E) b.b).put("systemDeterminedForeground", str);
                                        b.n(appStartTrace.s, "onDrawCount");
                                        z zVarA = appStartTrace.q.a();
                                        b.k();
                                        E.B((E) b.b, zVarA);
                                        appStartTrace.e(b);
                                        break;
                                    }
                                    break;
                                case 1:
                                    if (appStartTrace.n == null) {
                                        appStartTrace.n = new Timer();
                                        long j = appStartTrace.b().a;
                                        B b2 = appStartTrace.d;
                                        b2.o(j);
                                        b2.p(appStartTrace.b().b(appStartTrace.n));
                                        appStartTrace.e(b2);
                                        break;
                                    }
                                    break;
                                case 2:
                                    if (appStartTrace.o == null) {
                                        appStartTrace.o = new Timer();
                                        B bP3 = E.P();
                                        bP3.q("_experiment_preDrawFoQ");
                                        bP3.o(appStartTrace.b().a);
                                        bP3.p(appStartTrace.b().b(appStartTrace.o));
                                        E e2 = (E) bP3.h();
                                        B b3 = appStartTrace.d;
                                        b3.m(e2);
                                        appStartTrace.e(b3);
                                        break;
                                    }
                                    break;
                                default:
                                    Timer timer = AppStartTrace.v;
                                    B bP4 = E.P();
                                    bP4.q("_as");
                                    bP4.o(appStartTrace.a().a);
                                    bP4.p(appStartTrace.a().b(appStartTrace.k));
                                    ArrayList arrayList = new ArrayList(3);
                                    B bP5 = E.P();
                                    bP5.q("_astui");
                                    bP5.o(appStartTrace.a().a);
                                    bP5.p(appStartTrace.a().b(appStartTrace.i));
                                    arrayList.add((E) bP5.h());
                                    if (appStartTrace.j != null) {
                                        B bP6 = E.P();
                                        bP6.q("_astfd");
                                        bP6.o(appStartTrace.i.a);
                                        bP6.p(appStartTrace.i.b(appStartTrace.j));
                                        arrayList.add((E) bP6.h());
                                        B bP7 = E.P();
                                        bP7.q("_asti");
                                        bP7.o(appStartTrace.j.a);
                                        bP7.p(appStartTrace.j.b(appStartTrace.k));
                                        arrayList.add((E) bP7.h());
                                    }
                                    bP4.k();
                                    E.z((E) bP4.b, arrayList);
                                    z zVarA2 = appStartTrace.q.a();
                                    bP4.k();
                                    E.B((E) bP4.b, zVarA2);
                                    appStartTrace.b.c((E) bP4.h(), com.google.firebase.perf.v1.i.FOREGROUND_BACKGROUND);
                                    break;
                            }
                        }
                    }, new Runnable(this) { // from class: com.google.firebase.perf.metrics.a
                        public final /* synthetic */ AppStartTrace b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            AppStartTrace appStartTrace = this.b;
                            switch (i3) {
                                case 0:
                                    if (appStartTrace.p == null) {
                                        appStartTrace.p = new Timer();
                                        B bP = E.P();
                                        bP.q("_experiment_onDrawFoQ");
                                        bP.o(appStartTrace.b().a);
                                        bP.p(appStartTrace.b().b(appStartTrace.p));
                                        E e = (E) bP.h();
                                        B b = appStartTrace.d;
                                        b.m(e);
                                        if (appStartTrace.g != null) {
                                            B bP2 = E.P();
                                            bP2.q("_experiment_procStart_to_classLoad");
                                            bP2.o(appStartTrace.b().a);
                                            bP2.p(appStartTrace.b().b(appStartTrace.a()));
                                            b.m((E) bP2.h());
                                        }
                                        String str = appStartTrace.u ? "true" : "false";
                                        b.k();
                                        E.A((E) b.b).put("systemDeterminedForeground", str);
                                        b.n(appStartTrace.s, "onDrawCount");
                                        z zVarA = appStartTrace.q.a();
                                        b.k();
                                        E.B((E) b.b, zVarA);
                                        appStartTrace.e(b);
                                        break;
                                    }
                                    break;
                                case 1:
                                    if (appStartTrace.n == null) {
                                        appStartTrace.n = new Timer();
                                        long j = appStartTrace.b().a;
                                        B b2 = appStartTrace.d;
                                        b2.o(j);
                                        b2.p(appStartTrace.b().b(appStartTrace.n));
                                        appStartTrace.e(b2);
                                        break;
                                    }
                                    break;
                                case 2:
                                    if (appStartTrace.o == null) {
                                        appStartTrace.o = new Timer();
                                        B bP3 = E.P();
                                        bP3.q("_experiment_preDrawFoQ");
                                        bP3.o(appStartTrace.b().a);
                                        bP3.p(appStartTrace.b().b(appStartTrace.o));
                                        E e2 = (E) bP3.h();
                                        B b3 = appStartTrace.d;
                                        b3.m(e2);
                                        appStartTrace.e(b3);
                                        break;
                                    }
                                    break;
                                default:
                                    Timer timer = AppStartTrace.v;
                                    B bP4 = E.P();
                                    bP4.q("_as");
                                    bP4.o(appStartTrace.a().a);
                                    bP4.p(appStartTrace.a().b(appStartTrace.k));
                                    ArrayList arrayList = new ArrayList(3);
                                    B bP5 = E.P();
                                    bP5.q("_astui");
                                    bP5.o(appStartTrace.a().a);
                                    bP5.p(appStartTrace.a().b(appStartTrace.i));
                                    arrayList.add((E) bP5.h());
                                    if (appStartTrace.j != null) {
                                        B bP6 = E.P();
                                        bP6.q("_astfd");
                                        bP6.o(appStartTrace.i.a);
                                        bP6.p(appStartTrace.i.b(appStartTrace.j));
                                        arrayList.add((E) bP6.h());
                                        B bP7 = E.P();
                                        bP7.q("_asti");
                                        bP7.o(appStartTrace.j.a);
                                        bP7.p(appStartTrace.j.b(appStartTrace.k));
                                        arrayList.add((E) bP7.h());
                                    }
                                    bP4.k();
                                    E.z((E) bP4.b, arrayList);
                                    z zVarA2 = appStartTrace.q.a();
                                    bP4.k();
                                    E.B((E) bP4.b, zVarA2);
                                    appStartTrace.b.c((E) bP4.h(), com.google.firebase.perf.v1.i.FOREGROUND_BACKGROUND);
                                    break;
                            }
                        }
                    }));
                }
                if (this.k != null) {
                    return;
                }
                new WeakReference(activity);
                this.k = new Timer();
                this.q = SessionManager.getInstance().perfSession();
                com.google.firebase.perf.logging.a aVarD = com.google.firebase.perf.logging.a.d();
                activity.getClass();
                a().b(this.k);
                aVarD.a();
                final int i4 = 3;
                y.execute(new Runnable(this) { // from class: com.google.firebase.perf.metrics.a
                    public final /* synthetic */ AppStartTrace b;

                    {
                        this.b = this;
                    }

                    @Override // java.lang.Runnable
                    public final void run() {
                        AppStartTrace appStartTrace = this.b;
                        switch (i4) {
                            case 0:
                                if (appStartTrace.p == null) {
                                    appStartTrace.p = new Timer();
                                    B bP = E.P();
                                    bP.q("_experiment_onDrawFoQ");
                                    bP.o(appStartTrace.b().a);
                                    bP.p(appStartTrace.b().b(appStartTrace.p));
                                    E e = (E) bP.h();
                                    B b = appStartTrace.d;
                                    b.m(e);
                                    if (appStartTrace.g != null) {
                                        B bP2 = E.P();
                                        bP2.q("_experiment_procStart_to_classLoad");
                                        bP2.o(appStartTrace.b().a);
                                        bP2.p(appStartTrace.b().b(appStartTrace.a()));
                                        b.m((E) bP2.h());
                                    }
                                    String str = appStartTrace.u ? "true" : "false";
                                    b.k();
                                    E.A((E) b.b).put("systemDeterminedForeground", str);
                                    b.n(appStartTrace.s, "onDrawCount");
                                    z zVarA = appStartTrace.q.a();
                                    b.k();
                                    E.B((E) b.b, zVarA);
                                    appStartTrace.e(b);
                                    break;
                                }
                                break;
                            case 1:
                                if (appStartTrace.n == null) {
                                    appStartTrace.n = new Timer();
                                    long j = appStartTrace.b().a;
                                    B b2 = appStartTrace.d;
                                    b2.o(j);
                                    b2.p(appStartTrace.b().b(appStartTrace.n));
                                    appStartTrace.e(b2);
                                    break;
                                }
                                break;
                            case 2:
                                if (appStartTrace.o == null) {
                                    appStartTrace.o = new Timer();
                                    B bP3 = E.P();
                                    bP3.q("_experiment_preDrawFoQ");
                                    bP3.o(appStartTrace.b().a);
                                    bP3.p(appStartTrace.b().b(appStartTrace.o));
                                    E e2 = (E) bP3.h();
                                    B b3 = appStartTrace.d;
                                    b3.m(e2);
                                    appStartTrace.e(b3);
                                    break;
                                }
                                break;
                            default:
                                Timer timer = AppStartTrace.v;
                                B bP4 = E.P();
                                bP4.q("_as");
                                bP4.o(appStartTrace.a().a);
                                bP4.p(appStartTrace.a().b(appStartTrace.k));
                                ArrayList arrayList = new ArrayList(3);
                                B bP5 = E.P();
                                bP5.q("_astui");
                                bP5.o(appStartTrace.a().a);
                                bP5.p(appStartTrace.a().b(appStartTrace.i));
                                arrayList.add((E) bP5.h());
                                if (appStartTrace.j != null) {
                                    B bP6 = E.P();
                                    bP6.q("_astfd");
                                    bP6.o(appStartTrace.i.a);
                                    bP6.p(appStartTrace.i.b(appStartTrace.j));
                                    arrayList.add((E) bP6.h());
                                    B bP7 = E.P();
                                    bP7.q("_asti");
                                    bP7.o(appStartTrace.j.a);
                                    bP7.p(appStartTrace.j.b(appStartTrace.k));
                                    arrayList.add((E) bP7.h());
                                }
                                bP4.k();
                                E.z((E) bP4.b, arrayList);
                                z zVarA2 = appStartTrace.q.a();
                                bP4.k();
                                E.B((E) bP4.b, zVarA2);
                                appStartTrace.b.c((E) bP4.h(), com.google.firebase.perf.v1.i.FOREGROUND_BACKGROUND);
                                break;
                        }
                    }
                });
                if (!zF) {
                    f();
                }
            }
        } finally {
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityStarted(Activity activity) {
        if (!this.r && this.j == null && !this.f) {
            this.j = new Timer();
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
    }

    @Keep
    @InterfaceC1238a0(A.ON_STOP)
    public void onAppEnteredBackground() {
        if (this.r || this.f || this.m != null) {
            return;
        }
        this.m = new Timer();
        B bP = E.P();
        bP.q("_experiment_firstBackgrounding");
        bP.o(b().a);
        bP.p(b().b(this.m));
        this.d.m((E) bP.h());
    }

    @Keep
    @InterfaceC1238a0(A.ON_START)
    public void onAppEnteredForeground() {
        if (this.r || this.f || this.l != null) {
            return;
        }
        this.l = new Timer();
        B bP = E.P();
        bP.q("_experiment_firstForegrounding");
        bP.o(b().a);
        bP.p(b().b(this.l));
        this.d.m((E) bP.h());
    }
}
