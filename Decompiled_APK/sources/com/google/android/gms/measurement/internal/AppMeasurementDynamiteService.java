package com.google.android.gms.measurement.internal;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.collection.C0208f;
import com.google.android.gms.common.util.DynamiteApi;
import com.google.android.gms.internal.ads.C1719Ka;
import com.google.android.gms.internal.measurement.zzdh;
import com.google.android.gms.internal.measurement.zzdj;
import com.j256.ormlite.field.FieldType;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@DynamiteApi
/* loaded from: classes2.dex */
public class AppMeasurementDynamiteService extends com.google.android.gms.internal.measurement.I {
    public Y a;
    public final C0208f b;

    public static void $r8$lambda$W3cgi1t5N0SU6fYxM9Fsh5qQfPc(AppMeasurementDynamiteService appMeasurementDynamiteService, com.google.android.gms.internal.measurement.N n) {
        try {
            n.zze();
        } catch (RemoteException e) {
            Y y = appMeasurementDynamiteService.a;
            com.google.android.gms.common.internal.u.h(y);
            I i = y.i;
            Y.k(i);
            i.j.g("Failed to call IDynamiteUploadBatchesCallback", e);
        }
    }

    public AppMeasurementDynamiteService() {
        super("com.google.android.gms.measurement.api.internal.IAppMeasurementDynamiteService");
        this.a = null;
        this.b = new C0208f(0);
    }

    public final void X() {
        if (this.a == null) {
            throw new IllegalStateException("Attempting to perform action before initialize.");
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void beginAdUnitExposure(@NonNull String str, long j) throws RemoteException {
        X();
        C3884o c3884o = this.a.q;
        Y.g(c3884o);
        c3884o.T(j, str);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void clearConditionalUserProperty(@NonNull String str, @NonNull String str2, @NonNull Bundle bundle) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.X(str, str2, bundle);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void clearMeasurementEnabled(long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.Q();
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new A0(0, d0, null));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void endAdUnitExposure(@NonNull String str, long j) throws RemoteException {
        X();
        C3884o c3884o = this.a.q;
        Y.g(c3884o);
        c3884o.U(j, str);
    }

    public final void f0(String str, com.google.android.gms.internal.measurement.L l) {
        X();
        x1 x1Var = this.a.l;
        Y.h(x1Var);
        x1Var.t0(str, l);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void generateEventId(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        x1 x1Var = this.a.l;
        Y.h(x1Var);
        long jB1 = x1Var.b1();
        X();
        x1 x1Var2 = this.a.l;
        Y.h(x1Var2);
        x1Var2.s0(l, jB1);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getAppInstanceId(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        X x = this.a.j;
        Y.k(x);
        x.c0(new RunnableC3863d0(this, l, 0));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getCachedAppInstanceId(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        f0((String) d0.h.get(), l);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getConditionalUserProperties(String str, String str2, com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        X x = this.a.j;
        Y.k(x);
        x.c0(new RunnableC0069f(this, l, str, str2, 20));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getCurrentScreenClass(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        O0 o0 = ((Y) d0.b).o;
        Y.j(o0);
        L0 l0 = o0.d;
        f0(l0 != null ? l0.b : null, l);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getCurrentScreenName(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        O0 o0 = ((Y) d0.b).o;
        Y.j(o0);
        L0 l0 = o0.d;
        f0(l0 != null ? l0.a : null, l);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getGmpAppId(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        Y y = (Y) d0.b;
        String strG = null;
        if (y.g.f0(null, AbstractC3893t.p1) || y.s() == null) {
            try {
                strG = AbstractC3883n0.g(y.a, y.s);
            } catch (IllegalStateException e) {
                I i = y.i;
                Y.k(i);
                i.g.g("getGoogleAppId failed with exception", e);
            }
        } else {
            strG = y.s();
        }
        f0(strG, l);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getMaxUserProperties(String str, com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        com.google.android.gms.common.internal.u.e(str);
        ((Y) d0.b).getClass();
        X();
        x1 x1Var = this.a.l;
        Y.h(x1Var);
        x1Var.r0(l, 25);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getSessionId(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new androidx.camera.core.impl.utils.futures.h(d0, false, l, 26));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getTestFlag(com.google.android.gms.internal.measurement.L l, int i) throws RemoteException {
        X();
        if (i == 0) {
            x1 x1Var = this.a.l;
            Y.h(x1Var);
            D0 d0 = this.a.p;
            Y.j(d0);
            AtomicReference atomicReference = new AtomicReference();
            X x = ((Y) d0.b).j;
            Y.k(x);
            x1Var.t0((String) x.X(atomicReference, 15000L, "String test flag value", new RunnableC3896u0(d0, atomicReference, 2)), l);
            return;
        }
        if (i == 1) {
            x1 x1Var2 = this.a.l;
            Y.h(x1Var2);
            D0 d02 = this.a.p;
            Y.j(d02);
            AtomicReference atomicReference2 = new AtomicReference();
            X x2 = ((Y) d02.b).j;
            Y.k(x2);
            x1Var2.s0(l, ((Long) x2.X(atomicReference2, 15000L, "long test flag value", new RunnableC3892s0(d02, atomicReference2, 2))).longValue());
            return;
        }
        if (i == 2) {
            x1 x1Var3 = this.a.l;
            Y.h(x1Var3);
            D0 d03 = this.a.p;
            Y.j(d03);
            AtomicReference atomicReference3 = new AtomicReference();
            X x3 = ((Y) d03.b).j;
            Y.k(x3);
            double dDoubleValue = ((Double) x3.X(atomicReference3, 15000L, "double test flag value", new RunnableC3892s0(d03, atomicReference3, 3))).doubleValue();
            Bundle bundle = new Bundle();
            bundle.putDouble("r", dDoubleValue);
            try {
                l.t1(bundle);
                return;
            } catch (RemoteException e) {
                I i2 = ((Y) x1Var3.b).i;
                Y.k(i2);
                i2.j.g("Error returning double value to wrapper", e);
                return;
            }
        }
        if (i == 3) {
            x1 x1Var4 = this.a.l;
            Y.h(x1Var4);
            D0 d04 = this.a.p;
            Y.j(d04);
            AtomicReference atomicReference4 = new AtomicReference();
            X x4 = ((Y) d04.b).j;
            Y.k(x4);
            x1Var4.r0(l, ((Integer) x4.X(atomicReference4, 15000L, "int test flag value", new RunnableC3896u0(d04, atomicReference4, 3))).intValue());
            return;
        }
        if (i != 4) {
            return;
        }
        x1 x1Var5 = this.a.l;
        Y.h(x1Var5);
        D0 d05 = this.a.p;
        Y.j(d05);
        AtomicReference atomicReference5 = new AtomicReference();
        X x5 = ((Y) d05.b).j;
        Y.k(x5);
        x1Var5.n0(l, ((Boolean) x5.X(atomicReference5, 15000L, "boolean test flag value", new RunnableC3892s0(d05, atomicReference5, 1))).booleanValue());
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void getUserProperties(String str, String str2, boolean z, com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        X x = this.a.j;
        Y.k(x);
        x.c0(new RunnableC3906z0(this, l, str, str2, z, 0));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void initForTests(@NonNull Map map) throws RemoteException {
        X();
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void initialize(com.google.android.gms.dynamic.a aVar, zzdh zzdhVar, long j) throws RemoteException {
        Y y = this.a;
        if (y == null) {
            Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
            com.google.android.gms.common.internal.u.h(context);
            this.a = Y.q(context, zzdhVar, Long.valueOf(j));
        } else {
            I i = y.i;
            Y.k(i);
            i.j.f("Attempting to initialize multiple times");
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void isDataCollectionEnabled(com.google.android.gms.internal.measurement.L l) throws RemoteException {
        X();
        X x = this.a.j;
        Y.k(x);
        x.c0(new RunnableC3863d0(this, l, 1));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void logEvent(@NonNull String str, @NonNull String str2, @NonNull Bundle bundle, boolean z, boolean z2, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.b0(str, str2, bundle, z, z2, j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void logEventAndBundle(String str, String str2, Bundle bundle, com.google.android.gms.internal.measurement.L l, long j) throws RemoteException {
        X();
        com.google.android.gms.common.internal.u.e(str2);
        (bundle != null ? new Bundle(bundle) : new Bundle()).putString("_o", "app");
        zzbh zzbhVar = new zzbh(str2, new zzbf(bundle), "app", j);
        X x = this.a.j;
        Y.k(x);
        x.c0(new RunnableC0069f(this, l, zzbhVar, str, 16));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void logHealthData(int i, @NonNull String str, @NonNull com.google.android.gms.dynamic.a aVar, @NonNull com.google.android.gms.dynamic.a aVar2, @NonNull com.google.android.gms.dynamic.a aVar3) throws RemoteException {
        X();
        Object objI3 = aVar == null ? null : com.google.android.gms.dynamic.b.I3(aVar);
        Object objI32 = aVar2 == null ? null : com.google.android.gms.dynamic.b.I3(aVar2);
        Object objI33 = aVar3 != null ? com.google.android.gms.dynamic.b.I3(aVar3) : null;
        I i2 = this.a.i;
        Y.k(i2);
        i2.e0(i, true, false, str, objI3, objI32, objI33);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityCreated(@NonNull com.google.android.gms.dynamic.a aVar, @NonNull Bundle bundle, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityCreatedByScionActivityInfo(zzdj.a(activity), bundle, j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityCreatedByScionActivityInfo(zzdj zzdjVar, Bundle bundle, long j) {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        C0 c0 = d0.d;
        if (c0 != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
            c0.i(zzdjVar, bundle);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityDestroyed(@NonNull com.google.android.gms.dynamic.a aVar, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityDestroyedByScionActivityInfo(zzdj.a(activity), j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityDestroyedByScionActivityInfo(zzdj zzdjVar, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        C0 c0 = d0.d;
        if (c0 != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
            c0.j(zzdjVar);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityPaused(@NonNull com.google.android.gms.dynamic.a aVar, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityPausedByScionActivityInfo(zzdj.a(activity), j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityPausedByScionActivityInfo(zzdj zzdjVar, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        C0 c0 = d0.d;
        if (c0 != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
            c0.k(zzdjVar);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityResumed(@NonNull com.google.android.gms.dynamic.a aVar, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityResumedByScionActivityInfo(zzdj.a(activity), j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityResumedByScionActivityInfo(zzdj zzdjVar, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        C0 c0 = d0.d;
        if (c0 != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
            c0.l(zzdjVar);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivitySaveInstanceState(com.google.android.gms.dynamic.a aVar, com.google.android.gms.internal.measurement.L l, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivitySaveInstanceStateByScionActivityInfo(zzdj.a(activity), l, j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivitySaveInstanceStateByScionActivityInfo(zzdj zzdjVar, com.google.android.gms.internal.measurement.L l, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        C0 c0 = d0.d;
        Bundle bundle = new Bundle();
        if (c0 != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
            c0.m(zzdjVar, bundle);
        }
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = this.a.i;
            Y.k(i);
            i.j.g("Error returning bundle value to wrapper", e);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityStarted(@NonNull com.google.android.gms.dynamic.a aVar, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityStartedByScionActivityInfo(zzdj.a(activity), j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityStartedByScionActivityInfo(zzdj zzdjVar, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        if (d0.d != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityStopped(@NonNull com.google.android.gms.dynamic.a aVar, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        onActivityStoppedByScionActivityInfo(zzdj.a(activity), j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void onActivityStoppedByScionActivityInfo(zzdj zzdjVar, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        if (d0.d != null) {
            D0 d02 = this.a.p;
            Y.j(d02);
            d02.Y();
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void performAction(Bundle bundle, com.google.android.gms.internal.measurement.L l, long j) throws RemoteException {
        X();
        l.t1(null);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void registerOnMeasurementEventListener(com.google.android.gms.internal.measurement.P p) throws RemoteException {
        InterfaceC3887p0 u1Var;
        X();
        C0208f c0208f = this.b;
        synchronized (c0208f) {
            try {
                u1Var = (InterfaceC3887p0) c0208f.get(Integer.valueOf(p.zze()));
                if (u1Var == null) {
                    u1Var = new u1(this, p);
                    c0208f.put(Integer.valueOf(p.zze()), u1Var);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.g0(u1Var);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void resetAnalyticsData(long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.h.set(null);
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new RunnableC3904y0(d0, j, 1));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void retrieveAndUploadBatches(com.google.android.gms.internal.measurement.N n) throws MalformedURLException {
        J0 j0;
        X();
        C3864e c3864e = this.a.g;
        C3891s c3891s = AbstractC3893t.R0;
        if (c3864e.f0(null, c3891s)) {
            D0 d0 = this.a.p;
            Y.j(d0);
            Y y = (Y) d0.b;
            if (y.g.f0(null, c3891s)) {
                d0.Q();
                X x = y.j;
                Y.k(x);
                if (x.e0()) {
                    I i = y.i;
                    Y.k(i);
                    i.g.f("Cannot retrieve and upload batches from analytics worker thread");
                    return;
                }
                X x2 = y.j;
                Y.k(x2);
                if (Thread.currentThread() == x2.e) {
                    I i2 = y.i;
                    Y.k(i2);
                    i2.g.f("Cannot retrieve and upload batches from analytics network thread");
                    return;
                }
                if (com.google.android.material.shape.e.x()) {
                    I i3 = y.i;
                    Y.k(i3);
                    i3.g.f("Cannot retrieve and upload batches from main thread");
                    return;
                }
                I i4 = y.i;
                Y.k(i4);
                i4.o.f("[sgtm] Started client-side batch upload work.");
                boolean z = false;
                int size = 0;
                int i5 = 0;
                while (!z) {
                    I i6 = y.i;
                    Y.k(i6);
                    i6.o.f("[sgtm] Getting upload batches from service (FE)");
                    AtomicReference atomicReference = new AtomicReference();
                    X x3 = y.j;
                    Y.k(x3);
                    x3.X(atomicReference, 10000L, "[sgtm] Getting upload batches", new RunnableC3896u0(d0, atomicReference, 0));
                    zzpe zzpeVar = (zzpe) atomicReference.get();
                    if (zzpeVar == null) {
                        break;
                    }
                    List list = zzpeVar.a;
                    if (list.isEmpty()) {
                        break;
                    }
                    I i7 = y.i;
                    Y.k(i7);
                    i7.o.g("[sgtm] Retrieved upload batches. count", Integer.valueOf(list.size()));
                    size += list.size();
                    Iterator it2 = list.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            z = false;
                            break;
                        }
                        zzpa zzpaVar = (zzpa) it2.next();
                        try {
                            URL url = new URI(zzpaVar.c).toURL();
                            AtomicReference atomicReference2 = new AtomicReference();
                            A aN = ((Y) d0.b).n();
                            aN.Q();
                            com.google.android.gms.common.internal.u.h(aN.h);
                            String str = aN.h;
                            Y y2 = (Y) d0.b;
                            I i8 = y2.i;
                            Y.k(i8);
                            C1719Ka c1719Ka = i8.o;
                            Long lValueOf = Long.valueOf(zzpaVar.a);
                            c1719Ka.i("[sgtm] Uploading data from app. row_id, url, uncompressed size", lValueOf, zzpaVar.c, Integer.valueOf(zzpaVar.b.length));
                            if (!TextUtils.isEmpty(zzpaVar.g)) {
                                I i9 = y2.i;
                                Y.k(i9);
                                i9.o.h("[sgtm] Uploading data from app. row_id", lValueOf, zzpaVar.g);
                            }
                            HashMap map = new HashMap();
                            Bundle bundle = zzpaVar.d;
                            for (String str2 : bundle.keySet()) {
                                String string = bundle.getString(str2);
                                if (!TextUtils.isEmpty(string)) {
                                    map.put(str2, string);
                                }
                            }
                            H0 h0 = y2.r;
                            Y.k(h0);
                            byte[] bArr = zzpaVar.b;
                            com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(d0, atomicReference2, zzpaVar, 8);
                            h0.U();
                            com.google.android.gms.common.internal.u.h(url);
                            com.google.android.gms.common.internal.u.h(bArr);
                            X x4 = ((Y) h0.b).j;
                            Y.k(x4);
                            x4.b0(new L(h0, str, url, bArr, map, eVar));
                            try {
                                x1 x1Var = y2.l;
                                Y.h(x1Var);
                                Y y3 = (Y) x1Var.b;
                                y3.n.getClass();
                                long jCurrentTimeMillis = System.currentTimeMillis() + 60000;
                                synchronized (atomicReference2) {
                                    for (long jCurrentTimeMillis2 = 60000; atomicReference2.get() == null && jCurrentTimeMillis2 > 0; jCurrentTimeMillis2 = jCurrentTimeMillis - System.currentTimeMillis()) {
                                        try {
                                            atomicReference2.wait(jCurrentTimeMillis2);
                                            y3.n.getClass();
                                        } catch (Throwable th) {
                                            throw th;
                                        }
                                    }
                                }
                            } catch (InterruptedException unused) {
                                I i10 = ((Y) d0.b).i;
                                Y.k(i10);
                                i10.j.f("[sgtm] Interrupted waiting for uploading batch");
                            }
                            j0 = atomicReference2.get() == null ? J0.UNKNOWN : (J0) atomicReference2.get();
                        } catch (MalformedURLException | URISyntaxException e) {
                            I i11 = ((Y) d0.b).i;
                            Y.k(i11);
                            i11.g.i("[sgtm] Bad upload url for row_id", zzpaVar.c, Long.valueOf(zzpaVar.a), e);
                            j0 = J0.FAILURE;
                        }
                        if (j0 != J0.SUCCESS) {
                            if (j0 == J0.BACKOFF) {
                                z = true;
                                break;
                            }
                        } else {
                            i5++;
                        }
                    }
                }
                I i12 = y.i;
                Y.k(i12);
                i12.o.h("[sgtm] Completed client-side batch upload work. total, success", Integer.valueOf(size), Integer.valueOf(i5));
                $r8$lambda$W3cgi1t5N0SU6fYxM9Fsh5qQfPc(this, n);
            }
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setConditionalUserProperty(@NonNull Bundle bundle, long j) throws RemoteException {
        X();
        if (bundle == null) {
            I i = this.a.i;
            Y.k(i);
            i.g.f("Conditional user property must not be null");
        } else {
            D0 d0 = this.a.p;
            Y.j(d0);
            d0.h0(bundle, j);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setConsent(@NonNull Bundle bundle, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.d0(new com.android.volley.i(d0, bundle, j, 4, false));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setConsentThirdParty(@NonNull Bundle bundle, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.i0(bundle, -20, j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setCurrentScreen(@NonNull com.google.android.gms.dynamic.a aVar, @NonNull String str, @NonNull String str2, long j) throws RemoteException {
        X();
        Activity activity = (Activity) com.google.android.gms.dynamic.b.I3(aVar);
        com.google.android.gms.common.internal.u.h(activity);
        setCurrentScreenByScionActivityInfo(zzdj.a(activity), str, str2, j);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0088, code lost:
    
        if (r3 <= 500) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00b1, code lost:
    
        if (r3 <= 500) goto L39;
     */
    @Override // com.google.android.gms.internal.measurement.J
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setCurrentScreenByScionActivityInfo(com.google.android.gms.internal.measurement.zzdj r6, java.lang.String r7, java.lang.String r8, long r9) throws android.os.RemoteException {
        /*
            Method dump skipped, instructions count: 243
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.AppMeasurementDynamiteService.setCurrentScreenByScionActivityInfo(com.google.android.gms.internal.measurement.zzdj, java.lang.String, java.lang.String, long):void");
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setDataCollectionEnabled(boolean z) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.Q();
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new com.bumptech.glide.manager.o(z, 7, d0));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setDefaultEventParameters(@NonNull Bundle bundle) {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        Bundle bundle2 = bundle == null ? new Bundle() : new Bundle(bundle);
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new RunnableC3894t0(d0, bundle2, 0));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setEventInterceptor(com.google.android.gms.internal.measurement.P p) throws RemoteException {
        X();
        androidx.work.impl.model.l lVar = new androidx.work.impl.model.l(11, this, p);
        X x = this.a.j;
        Y.k(x);
        if (x.e0()) {
            D0 d0 = this.a.p;
            Y.j(d0);
            d0.k0(lVar);
        } else {
            X x2 = this.a.j;
            Y.k(x2);
            x2.c0(new A0(1, this, lVar));
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setInstanceIdProvider(com.google.android.gms.internal.measurement.S s) throws RemoteException {
        X();
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setMeasurementEnabled(boolean z, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        Boolean boolValueOf = Boolean.valueOf(z);
        d0.Q();
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new A0(0, d0, boolValueOf));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setMinimumSessionDuration(long j) throws RemoteException {
        X();
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setSessionTimeoutDuration(long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        X x = ((Y) d0.b).j;
        Y.k(x);
        x.c0(new RunnableC3904y0(d0, j, 0));
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setSgtmDebugInfo(@NonNull Intent intent) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        Uri data = intent.getData();
        Y y = (Y) d0.b;
        if (data == null) {
            I i = y.i;
            Y.k(i);
            i.m.f("Activity intent has no data. Preview Mode was not enabled.");
            return;
        }
        String queryParameter = data.getQueryParameter("sgtm_debug_enable");
        if (queryParameter == null || !queryParameter.equals("1")) {
            I i2 = y.i;
            Y.k(i2);
            i2.m.f("[sgtm] Preview Mode was not enabled.");
            y.g.d = null;
            return;
        }
        String queryParameter2 = data.getQueryParameter("sgtm_preview_key");
        if (TextUtils.isEmpty(queryParameter2)) {
            return;
        }
        I i3 = y.i;
        Y.k(i3);
        i3.m.g("[sgtm] Preview Mode was enabled. Using the sgtmPreviewKey: ", queryParameter2);
        y.g.d = queryParameter2;
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setUserId(@NonNull String str, long j) throws RemoteException {
        X();
        D0 d0 = this.a.p;
        Y.j(d0);
        Y y = (Y) d0.b;
        if (str != null && TextUtils.isEmpty(str)) {
            I i = y.i;
            Y.k(i);
            i.j.f("User ID must be non-empty or null");
        } else {
            X x = y.j;
            Y.k(x);
            x.c0(new com.google.common.util.concurrent.d(27, d0, str));
            d0.n0(null, FieldType.FOREIGN_ID_FIELD_SUFFIX, str, true, j);
        }
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void setUserProperty(@NonNull String str, @NonNull String str2, @NonNull com.google.android.gms.dynamic.a aVar, boolean z, long j) throws SecurityException, RemoteException {
        X();
        Object objI3 = com.google.android.gms.dynamic.b.I3(aVar);
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.n0(str, str2, objI3, z, j);
    }

    @Override // com.google.android.gms.internal.measurement.J
    public void unregisterOnMeasurementEventListener(com.google.android.gms.internal.measurement.P p) throws RemoteException {
        Object u1Var;
        X();
        C0208f c0208f = this.b;
        synchronized (c0208f) {
            u1Var = (InterfaceC3887p0) c0208f.remove(Integer.valueOf(p.zze()));
        }
        if (u1Var == null) {
            u1Var = new u1(this, p);
        }
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.Q();
        if (d0.f.remove(u1Var)) {
            return;
        }
        I i = ((Y) d0.b).i;
        Y.k(i);
        i.j.f("OnEventListener had not been registered");
    }
}
