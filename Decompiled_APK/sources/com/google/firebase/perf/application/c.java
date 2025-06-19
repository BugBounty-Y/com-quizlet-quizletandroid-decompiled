package com.google.firebase.perf.application;

import android.app.Activity;
import android.app.Application;
import android.os.Build;
import android.os.Bundle;
import android.util.SparseIntArray;
import androidx.fragment.app.AbstractC1124b0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import androidx.fragment.app.J;
import androidx.fragment.app.S;
import androidx.webkit.internal.p;
import com.google.android.gms.cloudmessaging.k;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.util.g;
import com.google.firebase.perf.v1.B;
import com.google.firebase.perf.v1.E;
import com.google.firebase.perf.v1.i;
import com.google.firebase.perf.v1.z;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements Application.ActivityLifecycleCallbacks {
    public static final com.google.firebase.perf.logging.a r = com.google.firebase.perf.logging.a.d();
    public static volatile c s;
    public final WeakHashMap a;
    public final WeakHashMap b;
    public final WeakHashMap c;
    public final WeakHashMap d;
    public final HashMap e;
    public final HashSet f;
    public final HashSet g;
    public final AtomicInteger h;
    public final com.google.firebase.perf.transport.f i;
    public final com.google.firebase.perf.config.a j;
    public final assistantMode.utils.studiableMetadata.b k;
    public final boolean l;
    public Timer m;
    public Timer n;
    public i o;
    public boolean p;
    public boolean q;

    public c(com.google.firebase.perf.transport.f fVar, assistantMode.utils.studiableMetadata.b bVar) {
        com.google.firebase.perf.config.a aVarE = com.google.firebase.perf.config.a.e();
        com.google.firebase.perf.logging.a aVar = f.e;
        this.a = new WeakHashMap();
        this.b = new WeakHashMap();
        this.c = new WeakHashMap();
        this.d = new WeakHashMap();
        this.e = new HashMap();
        this.f = new HashSet();
        this.g = new HashSet();
        this.h = new AtomicInteger(0);
        this.o = i.BACKGROUND;
        this.p = false;
        this.q = true;
        this.i = fVar;
        this.k = bVar;
        this.j = aVarE;
        this.l = true;
    }

    public static c a() {
        if (s == null) {
            synchronized (c.class) {
                try {
                    if (s == null) {
                        s = new c(com.google.firebase.perf.transport.f.s, new assistantMode.utils.studiableMetadata.b(19));
                    }
                } finally {
                }
            }
        }
        return s;
    }

    public final void b(String str) {
        synchronized (this.e) {
            try {
                Long l = (Long) this.e.get(str);
                if (l == null) {
                    this.e.put(str, 1L);
                } else {
                    this.e.put(str, Long.valueOf(l.longValue() + 1));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void c() {
        synchronized (this.g) {
            try {
                Iterator it2 = this.g.iterator();
                while (it2.hasNext()) {
                    if (((a) it2.next()) != null) {
                        try {
                            com.google.firebase.perf.logging.a aVar = com.google.firebase.perf.b.b;
                        } catch (IllegalStateException e) {
                            com.google.firebase.perf.c.a.g("FirebaseApp is not initialized. Firebase Performance will not be collecting any performance metrics until initialized. %s", e);
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d(Activity activity) {
        com.google.firebase.perf.util.d dVar;
        WeakHashMap weakHashMap = this.d;
        Trace trace = (Trace) weakHashMap.get(activity);
        if (trace == null) {
            return;
        }
        weakHashMap.remove(activity);
        f fVar = (f) this.b.get(activity);
        p pVar = fVar.b;
        boolean z = fVar.d;
        com.google.firebase.perf.logging.a aVar = f.e;
        if (z) {
            HashMap map = fVar.c;
            if (!map.isEmpty()) {
                aVar.a();
                map.clear();
            }
            com.google.firebase.perf.util.d dVarA = fVar.a();
            try {
                pVar.t(fVar.a);
            } catch (IllegalArgumentException | NullPointerException e) {
                if ((e instanceof NullPointerException) && Build.VERSION.SDK_INT > 28) {
                    throw e;
                }
                aVar.g("View not hardware accelerated. Unable to collect FrameMetrics. %s", e.toString());
                dVarA = new com.google.firebase.perf.util.d();
            }
            k kVar = (k) pVar.b;
            Object obj = kVar.c;
            kVar.c = new SparseIntArray[9];
            fVar.d = false;
            dVar = dVarA;
        } else {
            aVar.a();
            dVar = new com.google.firebase.perf.util.d();
        }
        if (dVar.b()) {
            g.a(trace, (com.google.firebase.perf.metrics.c) dVar.a());
            trace.stop();
        } else {
            r.g("Failed to record frame data for %s.", activity.getClass().getSimpleName());
        }
    }

    public final void e(String str, Timer timer, Timer timer2) {
        if (this.j.o()) {
            B bP = E.P();
            bP.q(str);
            bP.o(timer.a);
            bP.p(timer.b(timer2));
            z zVarA = SessionManager.getInstance().perfSession().a();
            bP.k();
            E.B((E) bP.b, zVarA);
            int andSet = this.h.getAndSet(0);
            synchronized (this.e) {
                try {
                    HashMap map = this.e;
                    bP.k();
                    E.x((E) bP.b).putAll(map);
                    if (andSet != 0) {
                        bP.n(andSet, "_tsns");
                    }
                    this.e.clear();
                } catch (Throwable th) {
                    throw th;
                }
            }
            this.i.c((E) bP.h(), i.FOREGROUND_BACKGROUND);
        }
    }

    public final void f(Activity activity) {
        if (this.l && this.j.o()) {
            f fVar = new f(activity);
            this.b.put(activity, fVar);
            if (activity instanceof I) {
                e cb = new e(this.k, this.i, this, fVar);
                this.c.put(activity, cb);
                J j = ((I) activity).getSupportFragmentManager().p;
                j.getClass();
                Intrinsics.checkNotNullParameter(cb, "cb");
                ((CopyOnWriteArrayList) j.b).add(new S(cb));
            }
        }
    }

    public final void g(i iVar) {
        this.o = iVar;
        synchronized (this.f) {
            try {
                Iterator it2 = this.f.iterator();
                while (it2.hasNext()) {
                    b bVar = (b) ((WeakReference) it2.next()).get();
                    if (bVar != null) {
                        bVar.onUpdateAppState(this.o);
                    } else {
                        it2.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        f(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        this.b.remove(activity);
        if (this.c.containsKey(activity)) {
            AbstractC1136h0 supportFragmentManager = ((I) activity).getSupportFragmentManager();
            AbstractC1124b0 cb = (AbstractC1124b0) this.c.remove(activity);
            J j = supportFragmentManager.p;
            j.getClass();
            Intrinsics.checkNotNullParameter(cb, "cb");
            synchronized (((CopyOnWriteArrayList) j.b)) {
                try {
                    int size = ((CopyOnWriteArrayList) j.b).size();
                    int i = 0;
                    while (true) {
                        if (i >= size) {
                            break;
                        }
                        if (((S) ((CopyOnWriteArrayList) j.b).get(i)).a == cb) {
                            ((CopyOnWriteArrayList) j.b).remove(i);
                            break;
                        }
                        i++;
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityResumed(Activity activity) {
        try {
            if (this.a.isEmpty()) {
                this.k.getClass();
                this.m = new Timer();
                this.a.put(activity, Boolean.TRUE);
                if (this.q) {
                    g(i.FOREGROUND);
                    c();
                    this.q = false;
                } else {
                    e("_bs", this.n, this.m);
                    g(i.FOREGROUND);
                }
            } else {
                this.a.put(activity, Boolean.TRUE);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityStarted(Activity activity) {
        try {
            if (this.l && this.j.o()) {
                if (!this.b.containsKey(activity)) {
                    f(activity);
                }
                ((f) this.b.get(activity)).b();
                Trace trace = new Trace("_st_".concat(activity.getClass().getSimpleName()), this.i, this.k, this);
                trace.start();
                this.d.put(activity, trace);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final synchronized void onActivityStopped(Activity activity) {
        try {
            if (this.l) {
                d(activity);
            }
            if (this.a.containsKey(activity)) {
                this.a.remove(activity);
                if (this.a.isEmpty()) {
                    this.k.getClass();
                    Timer timer = new Timer();
                    this.n = timer;
                    e("_fs", this.m, timer);
                    g(i.BACKGROUND);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}
