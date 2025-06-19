package com.facebook.appevents.iap;

import androidx.camera.camera2.internal.RunnableC0130g;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class m implements g {
    public static m I;
    public final Method A;
    public final Method B;
    public final Method C;
    public final Method D;
    public final Method E;
    public final Method F;
    public final Object a;
    public final Class b;
    public final Class c;
    public final Class d;
    public final Class e;
    public final Class f;
    public final Class g;
    public final Class h;
    public final Class i;
    public final Class j;
    public final Class k;
    public final Class l;
    public final Class m;
    public final Class n;
    public final Class o;
    public final Method p;
    public final Method q;
    public final Method r;
    public final Method s;
    public final Method t;
    public final Method u;
    public final Method v;
    public final Method w;
    public final Method x;
    public final Method y;
    public final Method z;
    public static final j G = new j(1);
    public static final AtomicBoolean H = new AtomicBoolean(false);
    public static final ConcurrentHashMap J = new ConcurrentHashMap();
    public static final ConcurrentHashMap K = new ConcurrentHashMap();
    public static final ConcurrentHashMap L = new ConcurrentHashMap();

    public m(Object obj, Class cls, Class cls2, Class cls3, Class cls4, Class cls5, Class cls6, Class cls7, Class cls8, Class cls9, Class cls10, Class cls11, Class cls12, Class cls13, Class cls14, Method method, Method method2, Method method3, Method method4, Method method5, Method method6, Method method7, Method method8, Method method9, Method method10, Method method11, Method method12, Method method13, Method method14, Method method15, Method method16, Method method17) {
        this.a = obj;
        this.b = cls;
        this.c = cls2;
        this.d = cls3;
        this.e = cls4;
        this.f = cls5;
        this.g = cls6;
        this.h = cls7;
        this.i = cls8;
        this.j = cls9;
        this.k = cls10;
        this.l = cls11;
        this.m = cls12;
        this.n = cls13;
        this.o = cls14;
        this.p = method;
        this.q = method2;
        this.r = method3;
        this.s = method4;
        this.t = method5;
        this.u = method6;
        this.v = method7;
        this.w = method8;
        this.x = method9;
        this.y = method10;
        this.z = method11;
        this.A = method12;
        this.B = method13;
        this.C = method14;
        this.D = method15;
        this.E = method16;
        this.F = method17;
    }

    public static final /* synthetic */ String b() {
        if (com.facebook.internal.instrument.crashshield.a.b(m.class)) {
            return null;
        }
        return "com.facebook.appevents.iap.m";
    }

    @Override // com.facebook.appevents.iap.g
    public final void a(t productType, Runnable completionHandler) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(productType, "productType");
            Intrinsics.checkNotNullParameter(completionHandler, "completionHandler");
            c(new RunnableC0130g(this, productType, completionHandler, 28));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void c(Runnable runnable) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            if (H.get()) {
                runnable.run();
                return;
            }
            Class cls = this.m;
            if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                return;
            }
            try {
                Object objNewProxyInstance = Proxy.newProxyInstance(cls.getClassLoader(), new Class[]{cls}, new k(this, new Object[]{runnable}));
                Class cls2 = this.b;
                Method method = this.E;
                Object obj = null;
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        obj = this.a;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th);
                    }
                }
                u.h(cls2, obj, method, objNewProxyInstance);
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(this, th2);
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(this, th3);
        }
    }

    public final String d(String productDetailsString) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Intrinsics.checkNotNullParameter(productDetailsString, "productDetailsString");
                kotlin.text.m mVarB = new Regex("jsonString='(.*?)'").b(productDetailsString);
                if (mVarB != null) {
                    return (String) CollectionsKt.O(1, mVarB.b());
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final Object e(t tVar, ArrayList arrayList) {
        Class cls = this.j;
        Class cls2 = this.l;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                if (!arrayList.isEmpty()) {
                    ArrayList arrayList2 = new ArrayList();
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        Object objH = u.h(cls2, u.h(cls2, u.h(cls2, u.h(this.f, null, this.z, new Object[0]), this.B, (String) it2.next()), this.C, tVar.a), this.A, new Object[0]);
                        if (objH != null) {
                            arrayList2.add(objH);
                        }
                    }
                    return u.h(cls, u.h(cls, u.h(this.h, null, this.w, new Object[0]), this.y, arrayList2), this.x, new Object[0]);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final void f(Object[] objArr, Object[] objArr2) {
        Runnable runnable;
        if (com.facebook.internal.instrument.crashshield.a.b(this) || objArr2 == null) {
            return;
        }
        try {
            if (objArr2.length == 0) {
                return;
            }
            if (Intrinsics.b(u.h(this.g, objArr2[0], this.F, new Object[0]), 0)) {
                H.set(true);
                if (objArr.length == 0) {
                    return;
                }
                Object obj = objArr[0];
                if (!(obj instanceof Runnable) || (runnable = (Runnable) obj) == null) {
                    return;
                }
                runnable.run();
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void g(Object[] objArr, Object[] objArr2) {
        String strD;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Object objF = C4933y.F(0, objArr);
            Object objF2 = objArr2 != null ? C4933y.F(1, objArr2) : null;
            if (objF2 != null && (objF2 instanceof List)) {
                Iterator it2 = ((List) objF2).iterator();
                while (it2.hasNext()) {
                    try {
                        Object objH = u.h(this.d, it2.next(), this.D, new Object[0]);
                        String str = objH instanceof String ? (String) objH : null;
                        if (str != null && (strD = d(str)) != null) {
                            JSONObject jSONObject = new JSONObject(strD);
                            if (jSONObject.has("productId")) {
                                String productId = jSONObject.getString("productId");
                                ConcurrentHashMap concurrentHashMap = L;
                                Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                concurrentHashMap.put(productId, jSONObject);
                            }
                        }
                    } catch (Exception unused) {
                    }
                }
                if (objF == null || !(objF instanceof Runnable)) {
                    return;
                }
                ((Runnable) objF).run();
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void h(Object[] objArr, Object[] objArr2) {
        Throwable th;
        Object objF;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Object objF2 = C4933y.F(0, objArr);
                if (objF2 != null && (objF2 instanceof t)) {
                    Object objF3 = C4933y.F(1, objArr);
                    if (objF3 instanceof Runnable) {
                        if (objArr2 != null) {
                            try {
                                objF = C4933y.F(1, objArr2);
                            } catch (Throwable th2) {
                                th = th2;
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                            }
                        } else {
                            objF = null;
                        }
                        if (objF != null && (objF instanceof List)) {
                            ArrayList arrayList = new ArrayList();
                            Iterator it2 = ((List) objF).iterator();
                            while (it2.hasNext()) {
                                try {
                                    Object objH = u.h(this.e, it2.next(), this.u, new Object[0]);
                                    String str = objH instanceof String ? (String) objH : null;
                                    if (str != null) {
                                        JSONObject jSONObject = new JSONObject(str);
                                        if (jSONObject.has("productId")) {
                                            String productId = jSONObject.getString("productId");
                                            if (!L.containsKey(productId)) {
                                                Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                                arrayList.add(productId);
                                            }
                                            if (objF2 == t.INAPP) {
                                                ConcurrentHashMap concurrentHashMap = J;
                                                Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                                concurrentHashMap.put(productId, jSONObject);
                                            } else {
                                                ConcurrentHashMap concurrentHashMap2 = K;
                                                Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                                concurrentHashMap2.put(productId, jSONObject);
                                            }
                                        }
                                    }
                                } catch (Exception unused) {
                                }
                            }
                            try {
                                if (arrayList.isEmpty()) {
                                    ((Runnable) objF3).run();
                                } else {
                                    t tVar = (t) objF2;
                                    Runnable runnable = (Runnable) objF3;
                                    if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                                        try {
                                            try {
                                                c(new androidx.camera.camera2.internal.compat.b(this, runnable, tVar, arrayList, 7));
                                            } catch (Throwable th3) {
                                                th = th3;
                                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                                            }
                                        } catch (Throwable th4) {
                                            th = th4;
                                        }
                                    }
                                }
                            } catch (Throwable th5) {
                                th = th5;
                                th = th;
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                            }
                        }
                    }
                }
            } catch (Throwable th6) {
                th = th6;
            }
        }
    }

    public final void i(Object[] objArr, Object[] objArr2) {
        Throwable th;
        Object objF;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Object objF2 = C4933y.F(0, objArr);
                if (objF2 != null && (objF2 instanceof t)) {
                    Object objF3 = C4933y.F(1, objArr);
                    if (objF3 instanceof Runnable) {
                        if (objArr2 != null) {
                            try {
                                objF = C4933y.F(1, objArr2);
                            } catch (Throwable th2) {
                                th = th2;
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                            }
                        } else {
                            objF = null;
                        }
                        if (objF != null && (objF instanceof List)) {
                            ArrayList arrayList = new ArrayList();
                            Iterator it2 = ((List) objF).iterator();
                            while (it2.hasNext()) {
                                Object objH = u.h(this.c, it2.next(), this.p, new Object[0]);
                                String str = objH instanceof String ? (String) objH : null;
                                if (str != null) {
                                    JSONObject jSONObject = new JSONObject(str);
                                    if (jSONObject.has("productId")) {
                                        String productId = jSONObject.getString("productId");
                                        if (!L.containsKey(productId)) {
                                            Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                            arrayList.add(productId);
                                        }
                                        if (objF2 == t.INAPP) {
                                            ConcurrentHashMap concurrentHashMap = J;
                                            Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                            concurrentHashMap.put(productId, jSONObject);
                                        } else {
                                            ConcurrentHashMap concurrentHashMap2 = K;
                                            Intrinsics.checkNotNullExpressionValue(productId, "productId");
                                            concurrentHashMap2.put(productId, jSONObject);
                                        }
                                    }
                                }
                            }
                            try {
                                if (arrayList.isEmpty()) {
                                    ((Runnable) objF3).run();
                                    return;
                                }
                                t tVar = (t) objF2;
                                Runnable runnable = (Runnable) objF3;
                                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                                    try {
                                        try {
                                            c(new androidx.camera.camera2.internal.compat.b(this, runnable, tVar, arrayList, 7));
                                        } catch (Throwable th3) {
                                            th = th3;
                                            com.facebook.internal.instrument.crashshield.a.a(this, th);
                                        }
                                    } catch (Throwable th4) {
                                        th = th4;
                                    }
                                }
                            } catch (Throwable th5) {
                                th = th5;
                                th = th;
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                            }
                        }
                    }
                }
            } catch (Throwable th6) {
                th = th6;
            }
        }
    }
}
