package com.google.android.gms.internal.ads;

import android.app.ActivityManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Looper;
import android.text.TextUtils;
import android.webkit.WebView;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.appsflyer.AppsFlyerProperties;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.WeakHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.Ob, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1744Ob implements InterfaceC1750Pb {
    public static final Object l = new Object();
    public static InterfaceC1750Pb m;
    public static InterfaceC1750Pb n;
    public static InterfaceC1750Pb o;
    public static Boolean p;
    public final Context b;
    public final VersionInfoParcel e;
    public final PackageInfo f;
    public final String g;
    public final String h;
    public boolean j;
    public final HashSet k;
    public final Object a = new Object();
    public final WeakHashMap c = new WeakHashMap();
    public final ExecutorService d = Executors.unconfigurableExecutorService(Executors.newCachedThreadPool());
    public final AtomicBoolean i = new AtomicBoolean();

    /* JADX WARN: Removed duplicated region for block: B:11:0x004d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C1744Ob(android.content.Context r4, com.google.android.gms.ads.internal.util.client.VersionInfoParcel r5) {
        /*
            r3 = this;
            r3.<init>()
            java.lang.Object r0 = new java.lang.Object
            r0.<init>()
            r3.a = r0
            java.util.WeakHashMap r0 = new java.util.WeakHashMap
            r0.<init>()
            r3.c = r0
            java.util.concurrent.ExecutorService r0 = java.util.concurrent.Executors.newCachedThreadPool()
            java.util.concurrent.ExecutorService r0 = java.util.concurrent.Executors.unconfigurableExecutorService(r0)
            r3.d = r0
            java.util.concurrent.atomic.AtomicBoolean r0 = new java.util.concurrent.atomic.AtomicBoolean
            r0.<init>()
            r3.i = r0
            android.content.Context r0 = r4.getApplicationContext()
            if (r0 == 0) goto L2c
            android.content.Context r4 = r4.getApplicationContext()
        L2c:
            r3.b = r4
            r3.e = r5
            com.google.android.gms.internal.ads.s7 r5 = com.google.android.gms.internal.ads.AbstractC2773w7.O7
            com.google.android.gms.ads.internal.client.r r0 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r0 = r0.c
            java.lang.Object r5 = r0.a(r5)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            boolean r5 = r5.booleanValue()
            r0 = 0
            if (r5 == 0) goto L4d
            com.google.android.gms.internal.ads.Ls r5 = com.google.android.gms.ads.internal.util.client.c.b
            if (r4 == 0) goto L4d
            android.content.pm.ApplicationInfo r5 = r4.getApplicationInfo()
            if (r5 != 0) goto L4f
        L4d:
            r4 = r0
            goto L5e
        L4f:
            com.google.android.gms.common.wrappers.b r5 = com.google.android.gms.common.wrappers.c.a(r4)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4d
            android.content.pm.ApplicationInfo r4 = r4.getApplicationInfo()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4d
            java.lang.String r4 = r4.packageName     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4d
            r1 = 0
            android.content.pm.PackageInfo r4 = r5.c(r4, r1)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4d
        L5e:
            r3.f = r4
            com.google.android.gms.internal.ads.s7 r4 = com.google.android.gms.internal.ads.AbstractC2773w7.M7
            com.google.android.gms.ads.internal.client.r r5 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r1 = r5.c
            java.lang.Object r1 = r1.a(r4)
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            java.lang.String r2 = "unknown"
            if (r1 == 0) goto L7f
            com.google.android.gms.internal.ads.Ls r1 = com.google.android.gms.ads.internal.util.client.c.b
            java.util.Locale r1 = java.util.Locale.getDefault()
            java.lang.String r1 = r1.getCountry()
            goto L80
        L7f:
            r1 = r2
        L80:
            r3.g = r1
            com.google.android.gms.internal.ads.u7 r5 = r5.c
            java.lang.Object r4 = r5.a(r4)
            java.lang.Boolean r4 = (java.lang.Boolean) r4
            boolean r4 = r4.booleanValue()
            if (r4 == 0) goto Lad
            android.content.Context r4 = r3.b
            com.google.android.gms.internal.ads.Ls r5 = com.google.android.gms.ads.internal.util.client.c.b
            if (r4 != 0) goto L97
            goto Lae
        L97:
            com.google.android.gms.common.wrappers.b r4 = com.google.android.gms.common.wrappers.c.a(r4)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> Lae
            java.lang.String r5 = "com.android.vending"
            r1 = 128(0x80, float:1.8E-43)
            android.content.pm.PackageInfo r4 = r4.c(r5, r1)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> Lae
            if (r4 != 0) goto La6
            goto Lae
        La6:
            int r4 = r4.versionCode     // Catch: android.content.pm.PackageManager.NameNotFoundException -> Lae
            java.lang.String r0 = java.lang.Integer.toString(r4)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> Lae
            goto Lae
        Lad:
            r0 = r2
        Lae:
            r3.h = r0
            com.google.android.gms.internal.ads.s7 r4 = com.google.android.gms.internal.ads.AbstractC2773w7.I7
            com.google.android.gms.ads.internal.client.r r5 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r5 = r5.c
            java.lang.Object r4 = r5.a(r4)
            java.lang.Integer r4 = (java.lang.Integer) r4
            int r4 = r4.intValue()
            if (r4 <= 0) goto Lc9
            java.util.HashSet r4 = new java.util.HashSet
            r4.<init>()
            r3.k = r4
        Lc9:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1744Ob.<init>(android.content.Context, com.google.android.gms.ads.internal.util.client.VersionInfoParcel):void");
    }

    public static InterfaceC1750Pb a(Context context) {
        synchronized (l) {
            try {
                if (m == null) {
                    if (i(context)) {
                        m = new C1744Ob(context, VersionInfoParcel.a());
                    } else {
                        m = new L9(14);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return m;
    }

    public static InterfaceC1750Pb b(Context context, VersionInfoParcel versionInfoParcel) {
        synchronized (l) {
            try {
                if (o == null) {
                    boolean z = false;
                    if (((Boolean) Q7.c.o()).booleanValue()) {
                        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G7)).booleanValue() || ((Boolean) Q7.a.o()).booleanValue()) {
                            z = true;
                        }
                    }
                    if (i(context)) {
                        C1744Ob c1744Ob = new C1744Ob(context, versionInfoParcel);
                        c1744Ob.h();
                        Thread.setDefaultUncaughtExceptionHandler(new C1738Nb(c1744Ob, Thread.getDefaultUncaughtExceptionHandler(), 0));
                        o = c1744Ob;
                    } else if (!z || context == null) {
                        o = new L9(14);
                    } else {
                        C1744Ob c1744Ob2 = new C1744Ob(context, versionInfoParcel);
                        c1744Ob2.j = true;
                        c1744Ob2.h();
                        Thread.setDefaultUncaughtExceptionHandler(new C1738Nb(c1744Ob2, Thread.getDefaultUncaughtExceptionHandler(), 0));
                        o = c1744Ob2;
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return o;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0037 A[Catch: all -> 0x0035, TryCatch #0 {all -> 0x0035, blocks: (B:4:0x0003, B:6:0x0007, B:8:0x0019, B:10:0x0029, B:13:0x0037, B:14:0x0040), top: B:19:0x0003 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.InterfaceC1750Pb c(android.content.Context r4) {
        /*
            java.lang.Object r0 = com.google.android.gms.internal.ads.C1744Ob.l
            monitor-enter(r0)
            com.google.android.gms.internal.ads.Pb r1 = com.google.android.gms.internal.ads.C1744Ob.n     // Catch: java.lang.Throwable -> L35
            if (r1 != 0) goto L40
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.H7     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.u7 r3 = r2.c     // Catch: java.lang.Throwable -> L35
            java.lang.Object r1 = r3.a(r1)     // Catch: java.lang.Throwable -> L35
            java.lang.Boolean r1 = (java.lang.Boolean) r1     // Catch: java.lang.Throwable -> L35
            boolean r1 = r1.booleanValue()     // Catch: java.lang.Throwable -> L35
            if (r1 == 0) goto L37
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.G7     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.u7 r2 = r2.c     // Catch: java.lang.Throwable -> L35
            java.lang.Object r1 = r2.a(r1)     // Catch: java.lang.Throwable -> L35
            java.lang.Boolean r1 = (java.lang.Boolean) r1     // Catch: java.lang.Throwable -> L35
            boolean r1 = r1.booleanValue()     // Catch: java.lang.Throwable -> L35
            if (r1 != 0) goto L37
            com.google.android.gms.internal.ads.Ob r1 = new com.google.android.gms.internal.ads.Ob     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r2 = com.google.android.gms.ads.internal.util.client.VersionInfoParcel.a()     // Catch: java.lang.Throwable -> L35
            r1.<init>(r4, r2)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.C1744Ob.n = r1     // Catch: java.lang.Throwable -> L35
            goto L40
        L35:
            r4 = move-exception
            goto L44
        L37:
            com.google.android.gms.internal.ads.L9 r4 = new com.google.android.gms.internal.ads.L9     // Catch: java.lang.Throwable -> L35
            r1 = 14
            r4.<init>(r1)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.C1744Ob.n = r4     // Catch: java.lang.Throwable -> L35
        L40:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.Pb r4 = com.google.android.gms.internal.ads.C1744Ob.n
            return r4
        L44:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L35
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1744Ob.c(android.content.Context):com.google.android.gms.internal.ads.Pb");
    }

    public static String f(Throwable th) {
        StringWriter stringWriter = new StringWriter();
        th.printStackTrace(new PrintWriter(stringWriter));
        return stringWriter.toString();
    }

    public static boolean i(Context context) {
        if (context != null) {
            synchronized (l) {
                try {
                    if (p == null) {
                        p = Boolean.valueOf(C1614q.f.e.nextInt(100) < ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Hc)).intValue());
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (p.booleanValue()) {
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G7)).booleanValue()) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1750Pb
    public final void d(String str, Throwable th) {
        if (this.j) {
            return;
        }
        e(th, str, 1.0f);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1750Pb
    public final void e(Throwable th, String str, float f) {
        Throwable th2;
        boolean zD;
        String packageName;
        ActivityManager activityManager;
        ActivityManager.MemoryInfo memoryInfo;
        String strA;
        Context context = this.b;
        if (this.j) {
            return;
        }
        Ls ls = com.google.android.gms.ads.internal.util.client.c.b;
        if (((Boolean) AbstractC2086g8.e.o()).booleanValue()) {
            th2 = th;
        } else {
            LinkedList linkedList = new LinkedList();
            for (Throwable cause = th; cause != null; cause = cause.getCause()) {
                linkedList.push(cause);
            }
            th2 = null;
            while (!linkedList.isEmpty()) {
                Throwable th3 = (Throwable) linkedList.pop();
                StackTraceElement[] stackTrace = th3.getStackTrace();
                boolean z = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s2)).booleanValue() && stackTrace != null && stackTrace.length == 0 && com.google.android.gms.ads.internal.util.client.c.j(th3.getClass().getName());
                ArrayList arrayList = new ArrayList();
                arrayList.add(new StackTraceElement(th3.getClass().getName(), "<filtered>", "<filtered>", 1));
                for (StackTraceElement stackTraceElement : stackTrace) {
                    if (com.google.android.gms.ads.internal.util.client.c.j(stackTraceElement.getClassName())) {
                        arrayList.add(stackTraceElement);
                        z = true;
                    } else {
                        String className = stackTraceElement.getClassName();
                        if (!TextUtils.isEmpty(className) && (className.startsWith("android.") || className.startsWith("java."))) {
                            arrayList.add(stackTraceElement);
                        } else {
                            arrayList.add(new StackTraceElement("<filtered>", "<filtered>", "<filtered>", 1));
                        }
                    }
                }
                if (z) {
                    th2 = th2 == null ? new Throwable(th3.getMessage()) : new Throwable(th3.getMessage(), th2);
                    th2.setStackTrace((StackTraceElement[]) arrayList.toArray(new StackTraceElement[0]));
                }
            }
        }
        if (th2 != null) {
            String name = th.getClass().getName();
            String strF = f(th);
            String str2 = "";
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P8)).booleanValue() && (strA = com.google.android.gms.ads.internal.util.client.c.a(f(th), "SHA-256")) != null) {
                str2 = strA;
            }
            double d = f;
            double dRandom = Math.random();
            int i = f > DefinitionKt.NO_Float_VALUE ? (int) (1.0f / f) : 1;
            if (dRandom < d) {
                ArrayList arrayList2 = new ArrayList();
                try {
                    zD = com.google.android.gms.common.wrappers.c.a(context).d();
                } catch (Throwable th4) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error fetching instant app info", th4);
                    zD = false;
                }
                try {
                    packageName = context.getPackageName();
                } catch (Throwable unused) {
                    com.google.android.gms.ads.internal.util.client.i.h("Cannot obtain package name, proceeding.");
                    packageName = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
                }
                Uri.Builder builderAppendQueryParameter = new Uri.Builder().scheme("https").path("//pagead2.googlesyndication.com/pagead/gen_204").appendQueryParameter("is_aia", Boolean.toString(zD)).appendQueryParameter("id", "gmob-apps-report-exception").appendQueryParameter("os", Build.VERSION.RELEASE).appendQueryParameter("api", String.valueOf(Build.VERSION.SDK_INT));
                String str3 = Build.MANUFACTURER;
                String strL = Build.MODEL;
                if (!strL.startsWith(str3)) {
                    strL = android.support.v4.media.session.a.l(str3, " ", strL);
                }
                Uri.Builder builderAppendQueryParameter2 = builderAppendQueryParameter.appendQueryParameter("device", strL);
                VersionInfoParcel versionInfoParcel = this.e;
                Uri.Builder builderAppendQueryParameter3 = builderAppendQueryParameter2.appendQueryParameter("js", versionInfoParcel.a).appendQueryParameter(AppsFlyerProperties.APP_ID, packageName).appendQueryParameter("exceptiontype", name).appendQueryParameter("stacktrace", strF);
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                Uri.Builder builderAppendQueryParameter4 = builderAppendQueryParameter3.appendQueryParameter("eids", TextUtils.join(",", rVar.a.h())).appendQueryParameter("exceptionkey", str).appendQueryParameter("cl", "756340629").appendQueryParameter("rc", "dev").appendQueryParameter("sampling_rate", Integer.toString(i)).appendQueryParameter("pb_tm", String.valueOf(AbstractC2086g8.c.o()));
                com.google.android.gms.common.c.b.getClass();
                Uri.Builder builderAppendQueryParameter5 = builderAppendQueryParameter4.appendQueryParameter("gmscv", String.valueOf(com.google.android.gms.common.c.a(context))).appendQueryParameter("lite", true != versionInfoParcel.e ? "0" : "1");
                if (!TextUtils.isEmpty(str2)) {
                    builderAppendQueryParameter5.appendQueryParameter("hash", str2);
                }
                C2601s7 c2601s7 = AbstractC2773w7.N7;
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue()) {
                    if (context == null || (activityManager = (ActivityManager) context.getSystemService("activity")) == null) {
                        memoryInfo = null;
                    } else {
                        memoryInfo = new ActivityManager.MemoryInfo();
                        try {
                            activityManager.getMemoryInfo(memoryInfo);
                        } catch (NullPointerException unused2) {
                            com.google.android.gms.ads.internal.util.client.i.h("Error retrieving the memory information.");
                        }
                    }
                    if (memoryInfo != null) {
                        builderAppendQueryParameter5.appendQueryParameter("available_memory", Long.toString(memoryInfo.availMem));
                        builderAppendQueryParameter5.appendQueryParameter("total_memory", Long.toString(memoryInfo.totalMem));
                        builderAppendQueryParameter5.appendQueryParameter("is_low_memory", true != memoryInfo.lowMemory ? "0" : "1");
                    }
                }
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.M7)).booleanValue()) {
                    String str4 = this.g;
                    if (!TextUtils.isEmpty(str4)) {
                        builderAppendQueryParameter5.appendQueryParameter("countrycode", str4);
                    }
                    String str5 = this.h;
                    if (!TextUtils.isEmpty(str5)) {
                        builderAppendQueryParameter5.appendQueryParameter("psv", str5);
                    }
                    PackageInfo currentWebViewPackage = WebView.getCurrentWebViewPackage();
                    if (currentWebViewPackage != null) {
                        builderAppendQueryParameter5.appendQueryParameter("wvvc", Integer.toString(currentWebViewPackage.versionCode));
                        builderAppendQueryParameter5.appendQueryParameter("wvvn", currentWebViewPackage.versionName);
                        builderAppendQueryParameter5.appendQueryParameter("wvpn", currentWebViewPackage.packageName);
                    }
                }
                PackageInfo packageInfo = this.f;
                if (packageInfo != null) {
                    builderAppendQueryParameter5.appendQueryParameter("appvc", String.valueOf(packageInfo.versionCode));
                    builderAppendQueryParameter5.appendQueryParameter("appvn", packageInfo.versionName);
                }
                arrayList2.add(builderAppendQueryParameter5.toString());
                Iterator it2 = arrayList2.iterator();
                while (it2.hasNext()) {
                    this.d.execute(new Qv(10, new com.google.android.gms.ads.internal.util.client.k(null), (String) it2.next()));
                }
            }
        }
    }

    public final void g(Throwable th) {
        Context context;
        SharedPreferences sharedPreferences;
        if (th != null) {
            boolean zJ = false;
            boolean zEquals = false;
            for (Throwable cause = th; cause != null; cause = cause.getCause()) {
                for (StackTraceElement stackTraceElement : cause.getStackTrace()) {
                    zJ |= com.google.android.gms.ads.internal.util.client.c.j(stackTraceElement.getClassName());
                    zEquals |= C1744Ob.class.getName().equals(stackTraceElement.getClassName());
                }
            }
            int iIntValue = ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I7)).intValue();
            if (iIntValue > 0) {
                HashSet hashSet = this.k;
                if (hashSet.size() >= iIntValue) {
                    return;
                }
                String strA = com.google.android.gms.ads.internal.util.client.c.a(f(th), "SHA-256");
                if (strA == null) {
                    strA = "";
                }
                if (hashSet.contains(strA)) {
                    return;
                } else {
                    hashSet.add(strA);
                }
            }
            if (!zJ || zEquals) {
                return;
            }
            if (!this.j) {
                d("", th);
            }
            if (this.i.getAndSet(true) || !((Boolean) Q7.c.o()).booleanValue() || (sharedPreferences = (context = this.b).getSharedPreferences("admob", 0)) == null) {
                return;
            }
            sharedPreferences.edit().putInt("crash_without_write", AbstractC1795We.I(context, "crash_without_write") + 1).commit();
        }
    }

    public final void h() {
        Thread thread = Looper.getMainLooper().getThread();
        if (thread == null) {
            return;
        }
        synchronized (this.a) {
            this.c.put(thread, Boolean.TRUE);
        }
        thread.setUncaughtExceptionHandler(new C1738Nb(this, thread.getUncaughtExceptionHandler(), 1));
    }
}
