package com.facebook.appevents.internal;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.facebook.internal.A;
import com.facebook.internal.J;
import com.facebook.internal.v;
import com.facebook.o;
import com.facebook.y;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Timer;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class b implements Application.ActivityLifecycleCallbacks {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivityCreated");
                c.b.execute(new RunnableC0131h(12));
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivityDestroyed");
                com.facebook.appevents.codeless.d dVar = com.facebook.appevents.codeless.d.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        com.facebook.appevents.codeless.g gVarA = com.facebook.appevents.codeless.g.f.a();
                        if (!com.facebook.internal.instrument.crashshield.a.b(gVarA)) {
                            try {
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                gVarA.e.remove(Integer.valueOf(activity.hashCode()));
                                break;
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(gVarA, th);
                                return;
                            }
                        }
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th2);
                        return;
                    }
                }
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        int i = 0;
        int i2 = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i2) {
            case 0:
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                y yVar = y.d;
                String str = c.a;
                com.google.mlkit.common.sdkinternal.model.a.v(yVar, str, "onActivityPaused");
                AtomicInteger atomicInteger = c.f;
                if (atomicInteger.decrementAndGet() < 0) {
                    atomicInteger.set(0);
                    Log.w(str, "Unexpected activity pause without a matching activity resume. Logging data may be incorrect. Make sure you call activateApp from your Application's onCreate method");
                }
                c.a();
                long jCurrentTimeMillis = System.currentTimeMillis();
                String strL = J.l(activity);
                com.facebook.appevents.codeless.d dVar = com.facebook.appevents.codeless.d.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        if (com.facebook.appevents.codeless.d.f.get()) {
                            com.facebook.appevents.codeless.g.f.a().c(activity);
                            com.facebook.appevents.codeless.k kVar = com.facebook.appevents.codeless.d.d;
                            if (kVar != null && !com.facebook.internal.instrument.crashshield.a.b(kVar)) {
                                try {
                                    if (((Activity) kVar.b.get()) != null) {
                                        try {
                                            Timer timer = kVar.c;
                                            if (timer != null) {
                                                timer.cancel();
                                            }
                                            kVar.c = null;
                                        } catch (Exception e) {
                                            Log.e(com.facebook.appevents.codeless.k.e, "Error unscheduling indexing job", e);
                                        }
                                    }
                                } catch (Throwable th) {
                                    com.facebook.internal.instrument.crashshield.a.a(kVar, th);
                                }
                            }
                            SensorManager sensorManager = com.facebook.appevents.codeless.d.c;
                            if (sensorManager != null) {
                                sensorManager.unregisterListener(com.facebook.appevents.codeless.d.b);
                            }
                        }
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th2);
                    }
                }
                c.b.execute(new a(i, jCurrentTimeMillis, strL));
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivityResumed");
                Intrinsics.checkNotNullParameter(activity, "activity");
                c.l = new WeakReference(activity);
                c.f.incrementAndGet();
                c.a();
                long jCurrentTimeMillis = System.currentTimeMillis();
                c.j = jCurrentTimeMillis;
                String strL = J.l(activity);
                com.facebook.appevents.codeless.d dVar = com.facebook.appevents.codeless.d.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        if (com.facebook.appevents.codeless.d.f.get()) {
                            com.facebook.appevents.codeless.g.f.a().a(activity);
                            Context applicationContext = activity.getApplicationContext();
                            String strB = o.b();
                            v vVarB = com.facebook.internal.y.b(strB);
                            com.facebook.appevents.codeless.d dVar2 = com.facebook.appevents.codeless.d.a;
                            if (vVarB == null || !vVarB.g) {
                                com.facebook.internal.instrument.crashshield.a.b(dVar2);
                            } else {
                                SensorManager sensorManager = (SensorManager) applicationContext.getSystemService("sensor");
                                if (sensorManager != null) {
                                    com.facebook.appevents.codeless.d.c = sensorManager;
                                    Sensor defaultSensor = sensorManager.getDefaultSensor(1);
                                    com.facebook.appevents.codeless.k kVar = new com.facebook.appevents.codeless.k(activity);
                                    com.facebook.appevents.codeless.d.d = kVar;
                                    com.facebook.appevents.codeless.l lVar = com.facebook.appevents.codeless.d.b;
                                    C0143u c0143u = new C0143u(16, vVarB, strB);
                                    if (!com.facebook.internal.instrument.crashshield.a.b(lVar)) {
                                        try {
                                            lVar.a = c0143u;
                                        } catch (Throwable th) {
                                            com.facebook.internal.instrument.crashshield.a.a(lVar, th);
                                        }
                                    }
                                    sensorManager.registerListener(lVar, defaultSensor, 2);
                                    if (vVarB.g) {
                                        kVar.c();
                                    }
                                }
                            }
                            com.facebook.internal.instrument.crashshield.a.b(dVar2);
                        }
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th2);
                    }
                }
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.aam.a.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        try {
                            if (com.facebook.appevents.aam.a.b) {
                                CopyOnWriteArraySet copyOnWriteArraySet = com.facebook.appevents.aam.c.d;
                                if (!new HashSet(com.facebook.appevents.aam.c.a()).isEmpty()) {
                                    HashMap map = com.facebook.appevents.aam.d.e;
                                    com.facebook.appevents.aam.a.b(activity);
                                }
                            }
                        } catch (Exception unused) {
                        }
                    } catch (Throwable th3) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.aam.a.class, th3);
                    }
                }
                com.facebook.appevents.suggestedevents.d.d(activity);
                String str = c.m;
                if (str != null && StringsKt.G(str, "ProxyBillingActivity", false) && !strL.equals("ProxyBillingActivity")) {
                    c.c.execute(new RunnableC0131h(11));
                }
                c.b.execute(new com.google.firebase.crashlytics.internal.common.o(activity.getApplicationContext(), strL, jCurrentTimeMillis));
                c.m = strL;
                break;
            default:
                h hVarA = h.b.a();
                if (hVarA != null) {
                    hVarA.b(activity);
                    break;
                }
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                Intrinsics.checkNotNullParameter(outState, "outState");
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivitySaveInstanceState");
                break;
            default:
                Intrinsics.checkNotNullParameter(outState, "bundle");
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                c.k++;
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivityStarted");
                break;
            default:
                h hVarA = h.b.a();
                if (hVarA != null) {
                    hVarA.b(activity);
                    break;
                }
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        int i = this.a;
        Intrinsics.checkNotNullParameter(activity, "activity");
        switch (i) {
            case 0:
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.d, c.a, "onActivityStopped");
                String str = com.facebook.appevents.j.c;
                com.bumptech.glide.f fVar = com.facebook.appevents.h.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.h.class)) {
                    try {
                        com.facebook.appevents.h.b.execute(new RunnableC0131h(6));
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.h.class, th);
                    }
                }
                c.k--;
                break;
        }
    }
}
