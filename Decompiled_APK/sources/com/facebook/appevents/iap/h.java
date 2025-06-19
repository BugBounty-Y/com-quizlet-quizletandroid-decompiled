package com.facebook.appevents.iap;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes.dex */
public final class h implements InvocationHandler {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.reflect.InvocationHandler
    public final Object invoke(Object proxy, Method m, Object[] objArr) throws Throwable {
        AtomicBoolean atomicBoolean;
        Method methodG;
        AtomicBoolean atomicBoolean2;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        Intrinsics.checkNotNullParameter(proxy, "proxy");
                        Intrinsics.checkNotNullParameter(m, "m");
                        if (Intrinsics.b(m.getName(), "onBillingSetupFinished")) {
                            Object objF = objArr != null ? C4933y.F(0, objArr) : null;
                            Class clsE = u.e("com.android.billingclient.api.BillingResult");
                            if (clsE != null && (methodG = u.g(clsE, "getResponseCode", new Class[0])) != null && Intrinsics.b(u.h(clsE, objF, methodG, new Object[0]), 0)) {
                                p pVar = l.l;
                                if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
                                    atomicBoolean2 = null;
                                    atomicBoolean2.set(true);
                                    ((Runnable) obj).run();
                                } else {
                                    try {
                                        atomicBoolean2 = l.n;
                                    } catch (Throwable th) {
                                        com.facebook.internal.instrument.crashshield.a.a(l.class, th);
                                    }
                                    atomicBoolean2.set(true);
                                    ((Runnable) obj).run();
                                }
                            }
                        } else {
                            String name = m.getName();
                            Intrinsics.checkNotNullExpressionValue(name, "m.name");
                            if (D.k(name, "onBillingServiceDisconnected", false)) {
                                p pVar2 = l.l;
                                if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
                                    atomicBoolean = null;
                                    atomicBoolean.set(false);
                                } else {
                                    try {
                                        atomicBoolean = l.n;
                                    } catch (Throwable th2) {
                                        com.facebook.internal.instrument.crashshield.a.a(l.class, th2);
                                    }
                                    atomicBoolean.set(false);
                                }
                            }
                        }
                    } catch (Throwable th3) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th3);
                    }
                }
                return null;
            default:
                try {
                    return Class.forName(m.getDeclaringClass().getName(), true, androidx.webkit.internal.p.class.getClassLoader()).getDeclaredMethod(m.getName(), m.getParameterTypes()).invoke((androidx.webkit.internal.p) obj, objArr);
                } catch (InvocationTargetException e) {
                    throw e.getTargetException();
                } catch (ReflectiveOperationException e2) {
                    throw new RuntimeException("Reflection failed for method " + m, e2);
                }
        }
    }
}
