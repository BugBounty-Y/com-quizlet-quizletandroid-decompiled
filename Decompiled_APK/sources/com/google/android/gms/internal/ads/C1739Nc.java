package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.Nc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1739Nc {
    public final AtomicReference a = new AtomicReference(null);
    public final Object b = new Object();
    public String c = null;
    public final AtomicBoolean d = new AtomicBoolean(false);
    public final AtomicInteger e = new AtomicInteger(-1);
    public final AtomicReference f = new AtomicReference(null);
    public final AtomicReference g = new AtomicReference(null);
    public final ConcurrentHashMap h = new ConcurrentHashMap(9);
    public final Object i;

    public C1739Nc() {
        new AtomicReference(null);
        new ArrayBlockingQueue(20);
        this.i = new Object();
    }

    public static final Bundle f(Map map) {
        Bundle bundle = new Bundle();
        if (map != null) {
            for (String str : map.keySet()) {
                try {
                    if (Objects.equals(str, "value")) {
                        bundle.putDouble(str, Double.parseDouble((String) map.get(str)));
                    } else {
                        bundle.putString(str, (String) map.get(str));
                    }
                } catch (NullPointerException | NumberFormatException unused) {
                }
            }
        }
        return bundle;
    }

    public static final boolean g(Context context) throws ClassNotFoundException {
        C2601s7 c2601s7 = AbstractC2773w7.q0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            int iA = com.google.android.gms.dynamite.c.a(context, ModuleDescriptor.MODULE_ID);
            C2601s7 c2601s72 = AbstractC2773w7.r0;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (iA >= ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue()) {
                if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.s0)).booleanValue()) {
                    return true;
                }
                try {
                    context.getClassLoader().loadClass("com.google.firebase.analytics.FirebaseAnalytics");
                    return false;
                } catch (ClassNotFoundException unused) {
                    return true;
                }
            }
        }
        return false;
    }

    public final String a(Context context) {
        Object objH;
        if (e(context) && (objH = h(context, "generateEventId")) != null) {
            return objH.toString();
        }
        return null;
    }

    public final String b(Context context) {
        if (e(context)) {
            C2601s7 c2601s7 = AbstractC2773w7.o0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            long jLongValue = ((Long) rVar.c.a(c2601s7)).longValue();
            if (jLongValue < 0) {
                return (String) h(context, "getAppInstanceId");
            }
            AtomicReference atomicReference = this.a;
            if (atomicReference.get() == null) {
                C2601s7 c2601s72 = AbstractC2773w7.p0;
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue(), ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue(), 1L, TimeUnit.MINUTES, new LinkedBlockingQueue(), new ThreadFactoryC1733Mc(0));
                while (!atomicReference.compareAndSet(null, threadPoolExecutor) && (atomicReference.get() == null || atomicReference.get() == null)) {
                }
            }
            try {
                return (String) ((ExecutorService) atomicReference.get()).submit(new A4(3, this, context)).get(jLongValue, TimeUnit.MILLISECONDS);
            } catch (TimeoutException unused) {
                return "TIME_OUT";
            } catch (Exception unused2) {
            }
        }
        return null;
    }

    public final String c(Context context) {
        if (!e(context)) {
            return null;
        }
        synchronized (this.b) {
            try {
                String str = this.c;
                if (str != null) {
                    return str;
                }
                String str2 = (String) h(context, "getGmpAppId");
                this.c = str2;
                return str2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d(int i, Context context, String str, String str2, String str3) {
        if (e(context)) {
            Bundle bundle = new Bundle();
            bundle.putString("_ai", str2);
            bundle.putString("reward_type", str3);
            bundle.putInt("reward_value", i);
            k(context, "_ar", str, bundle);
            com.google.android.gms.ads.internal.util.A.l("Log a Firebase reward video event, reward type: " + str3 + ", reward value: " + i);
        }
    }

    public final boolean e(Context context) {
        int iC;
        C2601s7 c2601s7 = AbstractC2773w7.i0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !this.d.get()) {
            if (!((Boolean) rVar.c.a(AbstractC2773w7.t0)).booleanValue()) {
                AtomicInteger atomicInteger = this.e;
                if (atomicInteger.get() == -1) {
                    com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                    com.google.android.gms.common.c cVar2 = com.google.android.gms.common.c.b;
                    if (cVar2.c(context, 12451000) != 0 && ((iC = cVar2.c(context, 12451000)) == 0 || iC == 2)) {
                        com.google.android.gms.ads.internal.util.client.i.h("Google Play Service is out of date, the Google Mobile Ads SDK will not integrate with Firebase. Admob/Firebase integration requires updated Google Play Service.");
                        atomicInteger.set(0);
                    } else {
                        atomicInteger.set(1);
                    }
                }
                if (atomicInteger.get() == 1) {
                }
            }
            return true;
        }
        return false;
    }

    public final Object h(Context context, String str) throws NoSuchMethodException, SecurityException {
        AtomicReference atomicReference = this.f;
        if (!m(context, "com.google.android.gms.measurement.AppMeasurement", atomicReference, true)) {
            return null;
        }
        try {
            return i(context, str).invoke(atomicReference.get(), null);
        } catch (Exception unused) {
            l(str, true);
            return null;
        }
    }

    public final Method i(Context context, String str) throws NoSuchMethodException, SecurityException {
        ConcurrentHashMap concurrentHashMap = this.h;
        Method method = (Method) concurrentHashMap.get(str);
        if (method != null) {
            return method;
        }
        try {
            Method declaredMethod = context.getClassLoader().loadClass("com.google.android.gms.measurement.AppMeasurement").getDeclaredMethod(str, null);
            concurrentHashMap.put(str, declaredMethod);
            return declaredMethod;
        } catch (Exception unused) {
            l(str, false);
            return null;
        }
    }

    public final void j(Context context, String str, String str2) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        AtomicReference atomicReference = this.f;
        if (m(context, "com.google.android.gms.measurement.AppMeasurement", atomicReference, true)) {
            ConcurrentHashMap concurrentHashMap = this.h;
            Method declaredMethod = (Method) concurrentHashMap.get(str2);
            if (declaredMethod == null) {
                try {
                    declaredMethod = context.getClassLoader().loadClass("com.google.android.gms.measurement.AppMeasurement").getDeclaredMethod(str2, String.class);
                    concurrentHashMap.put(str2, declaredMethod);
                } catch (Exception unused) {
                    l(str2, false);
                    declaredMethod = null;
                }
            }
            try {
                declaredMethod.invoke(atomicReference.get(), str);
                com.google.android.gms.ads.internal.util.A.l("Invoke Firebase method " + str2 + ", Ad Unit Id: " + str);
            } catch (Exception unused2) {
                l(str2, false);
            }
        }
    }

    public final void k(Context context, String str, String str2, Bundle bundle) {
        if (e(context)) {
            Bundle bundle2 = new Bundle();
            try {
                bundle2.putLong("_aeid", Long.parseLong(str2));
            } catch (NullPointerException | NumberFormatException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Invalid event ID: ".concat(String.valueOf(str2)), e);
            }
            if ("_ac".equals(str)) {
                bundle2.putInt("_r", 1);
            }
            if (bundle != null) {
                bundle2.putAll(bundle);
            }
            AtomicReference atomicReference = this.f;
            if (m(context, "com.google.android.gms.measurement.AppMeasurement", atomicReference, true)) {
                ConcurrentHashMap concurrentHashMap = this.h;
                Method declaredMethod = (Method) concurrentHashMap.get("logEventInternal");
                if (declaredMethod == null) {
                    try {
                        declaredMethod = context.getClassLoader().loadClass("com.google.android.gms.measurement.AppMeasurement").getDeclaredMethod("logEventInternal", String.class, String.class, Bundle.class);
                        concurrentHashMap.put("logEventInternal", declaredMethod);
                    } catch (Exception unused) {
                        l("logEventInternal", true);
                        declaredMethod = null;
                    }
                }
                try {
                    declaredMethod.invoke(atomicReference.get(), "am", str, bundle2);
                } catch (Exception unused2) {
                    l("logEventInternal", true);
                }
            }
        }
    }

    public final void l(String str, boolean z) {
        AtomicBoolean atomicBoolean = this.d;
        if (atomicBoolean.get()) {
            return;
        }
        com.google.android.gms.ads.internal.util.client.i.h("Invoke Firebase method " + str + " error.");
        if (z) {
            com.google.android.gms.ads.internal.util.client.i.h("The Google Mobile Ads SDK will not integrate with Firebase. Admob/Firebase integration requires the latest Firebase SDK jar, but Firebase SDK is either missing or out of date");
            atomicBoolean.set(true);
        }
    }

    public final boolean m(Context context, String str, AtomicReference atomicReference, boolean z) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        if (atomicReference.get() != null) {
            return true;
        }
        try {
            Object objInvoke = context.getClassLoader().loadClass(str).getDeclaredMethod("getInstance", Context.class).invoke(null, context);
            while (!atomicReference.compareAndSet(null, objInvoke)) {
                if (atomicReference.get() != null && atomicReference.get() != null) {
                    return true;
                }
            }
            return true;
        } catch (Exception unused) {
            l("getInstance", z);
            return false;
        }
    }
}
