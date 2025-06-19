package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Looper;
import android.util.Pair;
import com.amazon.device.ads.DtbConstants;
import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.google.android.gms.tasks.Task;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.I;

/* loaded from: classes3.dex */
public final class i {
    public final long a;
    public final long b;
    public final com.snowplowanalytics.core.utils.a c;
    public final List d;
    public final com.snowplowanalytics.snowplow.tracker.d e;
    public final Activity f;
    public final HashMap g;
    public boolean h;
    public long i;
    public long j;

    public i(List list, com.snowplowanalytics.snowplow.tracker.d retriever, Activity context) {
        com.snowplowanalytics.core.utils.a deviceInfoMonitor = new com.snowplowanalytics.core.utils.a();
        Intrinsics.checkNotNullParameter(deviceInfoMonitor, "deviceInfoMonitor");
        Intrinsics.checkNotNullParameter(retriever, "retriever");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = 1000L;
        this.b = 10000L;
        this.c = deviceInfoMonitor;
        this.d = list;
        this.e = retriever;
        this.f = context;
        this.g = new HashMap();
    }

    public final void a() {
        NetworkInfo activeNetworkInfo;
        this.j = System.currentTimeMillis();
        boolean zD = d(com.snowplowanalytics.snowplow.configuration.f.b);
        boolean zD2 = d(com.snowplowanalytics.snowplow.configuration.f.c);
        if (zD || zD2) {
            this.c.getClass();
            Activity context = this.f;
            Intrinsics.checkNotNullParameter(context, "context");
            Object systemService = context.getSystemService("connectivity");
            NetworkInfo networkInfo = null;
            ConnectivityManager connectivityManager = systemService instanceof ConnectivityManager ? (ConnectivityManager) systemService : null;
            if (connectivityManager != null) {
                try {
                    activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                } catch (SecurityException e) {
                    Intrinsics.checkNotNullExpressionValue("i", "TrackerConfiguration.TAG");
                    e.b("i", "Security exception getting NetworkInfo: %s", e.toString());
                }
            } else {
                activeNetworkInfo = null;
            }
            if (activeNetworkInfo != null) {
                if (activeNetworkInfo.isConnected()) {
                    networkInfo = activeNetworkInfo;
                }
            }
            HashMap map = this.g;
            com.snowplowanalytics.snowplow.tracker.d dVar = this.e;
            if (zD) {
                dVar.getClass();
                E6.a("networkType", new g(this, networkInfo, 0).invoke(), map);
            }
            if (zD2) {
                dVar.getClass();
                E6.a("networkTechnology", new g(this, networkInfo, 1).invoke(), map);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b() {
        /*
            Method dump skipped, instructions count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.snowplowanalytics.core.tracker.i.b():void");
    }

    public final void c() {
        Object objA;
        Object objA2;
        Object objA3;
        this.e.getClass();
        new h(this, 5).invoke();
        HashMap map = this.g;
        E6.a("osType", DtbConstants.NATIVE_OS_NAME, map);
        new h(this, 6).invoke();
        E6.a(DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY, Build.VERSION.RELEASE, map);
        new h(this, 7).invoke();
        E6.a("deviceModel", Build.MODEL, map);
        new h(this, 8).invoke();
        E6.a("deviceManufacturer", Build.MANUFACTURER, map);
        if (d(com.snowplowanalytics.snowplow.configuration.f.a)) {
            E6.a("carrier", new h(this, 9).invoke(), map);
        }
        if (d(com.snowplowanalytics.snowplow.configuration.f.e)) {
            E6.a("physicalMemory", new h(this, 10).invoke(), map);
        }
        if (d(com.snowplowanalytics.snowplow.configuration.f.j)) {
            E6.a("totalStorage", new h(this, 11).invoke(), map);
        }
        if (d(com.snowplowanalytics.snowplow.configuration.f.l)) {
            E6.a("resolution", new h(this, 12).invoke(), map);
        }
        if (d(com.snowplowanalytics.snowplow.configuration.f.m)) {
            E6.a("scale", new h(this, 13).invoke(), map);
        }
        Pair pair = null;
        if (d(com.snowplowanalytics.snowplow.configuration.f.n)) {
            String str = (String) new h(this, 3).invoke();
            E6.a("language", str != null ? I.C(8, str) : null, map);
        }
        if (d(com.snowplowanalytics.snowplow.configuration.f.d)) {
            E6.a("androidIdfa", new h(this, 4).invoke(), map);
        }
        boolean zD = d(com.snowplowanalytics.snowplow.configuration.f.o);
        boolean zD2 = d(com.snowplowanalytics.snowplow.configuration.f.p);
        if (zD || zD2) {
            this.c.getClass();
            Activity context = this.f;
            Intrinsics.checkNotNullParameter(context, "context");
            if (!Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                try {
                    Object objB = com.snowplowanalytics.core.utils.a.b("com.google.android.gms.appset.AppSet", "getClient", new Class[]{Context.class}, context);
                    if (objB != null && (objA = com.snowplowanalytics.core.utils.a.a(objB, "getAppSetIdInfo", new Object[0])) != null) {
                        Intrinsics.checkNotNullExpressionValue(Task.class, "forName(\"com.google.android.gms.tasks.Task\")");
                        Object objB2 = com.snowplowanalytics.core.utils.a.b("com.google.android.gms.tasks.Tasks", "await", new Class[]{Task.class}, objA);
                        if (objB2 != null && (objA2 = com.snowplowanalytics.core.utils.a.a(objB2, "getId", new Object[0])) != null && (objA3 = com.snowplowanalytics.core.utils.a.a(objB2, "getScope", new Object[0])) != null) {
                            pair = new Pair((String) objA2, ((Integer) objA3).intValue() == 1 ? "app" : "developer");
                        }
                    }
                } catch (ClassNotFoundException unused) {
                    Intrinsics.checkNotNullExpressionValue("a", "TAG");
                    e.a("a", "AppSetID error: Google Play Services not found", new Object[0]);
                } catch (InvocationTargetException unused2) {
                    Intrinsics.checkNotNullExpressionValue("a", "TAG");
                    e.a("a", "AppSetID error: Google Play Services not available", new Object[0]);
                } catch (Exception unused3) {
                    Intrinsics.checkNotNullExpressionValue("a", "TAG");
                    e.a("a", "AppSetID error: couldn't connect to Google Play Services", new Object[0]);
                }
            }
            if (zD) {
                E6.a("appSetId", (String) new f(pair, 0).invoke(), map);
            }
            if (zD2) {
                E6.a("appSetIdScope", (String) new f(pair, 1).invoke(), map);
            }
        }
        this.h = true;
    }

    public final boolean d(com.snowplowanalytics.snowplow.configuration.f fVar) {
        List list = this.d;
        if (list != null) {
            return list.contains(fVar);
        }
        return true;
    }
}
