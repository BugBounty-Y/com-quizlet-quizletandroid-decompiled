package com.facebook.appevents.iap;

import androidx.camera.camera2.internal.RunnableC0130g;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l implements g {
    public static l m;
    public final Object a;
    public final Class b;
    public final Class c;
    public final Class d;
    public final Class e;
    public final Class f;
    public final Method g;
    public final Method h;
    public final Method i;
    public final Method j;
    public final r k;
    public static final p l = new p();
    public static final AtomicBoolean n = new AtomicBoolean(false);
    public static final ConcurrentHashMap o = new ConcurrentHashMap();
    public static final ConcurrentHashMap p = new ConcurrentHashMap();
    public static final ConcurrentHashMap q = new ConcurrentHashMap();

    public l(Object obj, Class cls, Class cls2, Class cls3, Class cls4, Class cls5, Method method, Method method2, Method method3, Method method4, r rVar) {
        this.a = obj;
        this.b = cls;
        this.c = cls2;
        this.d = cls3;
        this.e = cls4;
        this.f = cls5;
        this.g = method;
        this.h = method2;
        this.i = method3;
        this.j = method4;
        this.k = rVar;
    }

    public static final /* synthetic */ String b() {
        if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
            return null;
        }
        return "com.facebook.appevents.iap.l";
    }

    @Override // com.facebook.appevents.iap.g
    public final void a(t productType, Runnable completionHandler) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(productType, "productType");
            Intrinsics.checkNotNullParameter(completionHandler, "completionHandler");
            c(new RunnableC0130g(this, productType, completionHandler, 27));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void c(Runnable runnable) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            if (n.get()) {
                runnable.run();
            } else {
                d(runnable);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void d(Runnable runnable) {
        Method methodG;
        Class cls = this.b;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Class clsE = u.e("com.android.billingclient.api.BillingClientStateListener");
            if (clsE == null || (methodG = u.g(cls, "startConnection", clsE)) == null) {
                return;
            }
            Object objNewProxyInstance = Proxy.newProxyInstance(clsE.getClassLoader(), new Class[]{clsE}, new h(runnable, 0));
            Object obj = null;
            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                try {
                    obj = this.a;
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                }
            }
            u.h(cls, obj, methodG, objNewProxyInstance);
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }
}
