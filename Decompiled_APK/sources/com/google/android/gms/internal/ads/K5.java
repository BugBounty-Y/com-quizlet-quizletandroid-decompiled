package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class K5 implements Application.ActivityLifecycleCallbacks {
    public Activity a;
    public Application b;
    public RunnableC1989e h;
    public long j;
    public final Object c = new Object();
    public boolean d = true;
    public boolean e = false;
    public final ArrayList f = new ArrayList();
    public final ArrayList g = new ArrayList();
    public boolean i = false;

    public final void a(Activity activity) {
        synchronized (this.c) {
            try {
                if (!activity.getClass().getName().startsWith("com.google.android.gms.ads")) {
                    this.a = activity;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        synchronized (this.c) {
            try {
                Activity activity2 = this.a;
                if (activity2 == null) {
                    return;
                }
                if (activity2.equals(activity)) {
                    this.a = null;
                }
                Iterator it2 = this.g.iterator();
                while (it2.hasNext()) {
                    if (it2.next() != null) {
                        throw new ClassCastException();
                    }
                    try {
                        throw null;
                    } catch (Exception e) {
                        com.google.android.gms.ads.internal.j.C.h.h("AppActivityTracker.ActivityListener.onActivityDestroyed", e);
                        com.google.android.gms.ads.internal.util.client.i.f("", e);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        a(activity);
        synchronized (this.c) {
            Iterator it2 = this.g.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                try {
                    throw null;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.j.C.h.h("AppActivityTracker.ActivityListener.onActivityPaused", e);
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                }
            }
        }
        this.e = true;
        RunnableC1989e runnableC1989e = this.h;
        if (runnableC1989e != null) {
            com.google.android.gms.ads.internal.util.F.l.removeCallbacks(runnableC1989e);
        }
        com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
        RunnableC1989e runnableC1989e2 = new RunnableC1989e(this, 7);
        this.h = runnableC1989e2;
        b.postDelayed(runnableC1989e2, this.j);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        a(activity);
        this.e = false;
        boolean z = this.d;
        this.d = true;
        RunnableC1989e runnableC1989e = this.h;
        if (runnableC1989e != null) {
            com.google.android.gms.ads.internal.util.F.l.removeCallbacks(runnableC1989e);
        }
        synchronized (this.c) {
            Iterator it2 = this.g.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                try {
                    throw null;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.j.C.h.h("AppActivityTracker.ActivityListener.onActivityResumed", e);
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                }
            }
            if (z) {
                com.google.android.gms.ads.internal.util.client.i.d("App is still foreground.");
            } else {
                Iterator it3 = this.f.iterator();
                while (it3.hasNext()) {
                    try {
                        ((L5) it3.next()).V(true);
                    } catch (Exception e2) {
                        com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    }
                }
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        a(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
    }
}
