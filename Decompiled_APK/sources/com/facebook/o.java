package com.facebook;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.util.Log;
import androidx.camera.camera2.internal.s0;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C;
import com.facebook.internal.C1549d;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import com.facebook.internal.J;
import com.google.android.gms.internal.mlkit_vision_common.D;
import com.google.android.gms.internal.mlkit_vision_common.I;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.collections.a0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o {
    public static final o a = new o();
    public static final HashSet b = a0.c(y.e);
    public static Executor c;
    public static volatile String d;
    public static volatile String e;
    public static volatile String f;
    public static volatile Boolean g;
    public static Context h;
    public static int i;
    public static final ReentrantLock j;
    public static final String k;
    public static boolean l;
    public static boolean m;
    public static boolean n;
    public static final AtomicBoolean o;
    public static volatile String p;
    public static volatile String q;
    public static final s0 r;
    public static boolean s;

    static {
        new AtomicLong(65536L);
        i = 64206;
        j = new ReentrantLock();
        k = "v16.0";
        o = new AtomicBoolean(false);
        p = "instagram.com";
        q = "facebook.com";
        r = new s0(20);
    }

    public static final Context a() {
        AbstractC1554i.k();
        Context context = h;
        if (context != null) {
            return context;
        }
        Intrinsics.m("applicationContext");
        throw null;
    }

    public static final String b() {
        AbstractC1554i.k();
        String str = d;
        if (str != null) {
            return str;
        }
        throw new FacebookException("A valid Facebook app id must be set in the AndroidManifest.xml or set by calling FacebookSdk.setApplicationId before initializing the sdk.");
    }

    public static final Executor c() {
        ReentrantLock reentrantLock = j;
        reentrantLock.lock();
        try {
            if (c == null) {
                c = AsyncTask.THREAD_POOL_EXECUTOR;
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            Executor executor = c;
            if (executor != null) {
                return executor;
            }
            throw new IllegalStateException("Required value was null.");
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String d() {
        String str = k;
        Intrinsics.checkNotNullExpressionValue(String.format("getGraphApiVersion: %s", Arrays.copyOf(new Object[]{str}, 1)), "format(format, *args)");
        return str;
    }

    public static final String e() {
        Date date = AccessToken.l;
        AccessToken accessTokenC = D.c();
        String str = accessTokenC != null ? accessTokenC.k : null;
        String str2 = q;
        if (str != null) {
            if (str.equals("gaming")) {
                return kotlin.text.D.o(str2, "facebook.com", "fb.gg", false);
            }
            if (str.equals("instagram")) {
                return kotlin.text.D.o(str2, "facebook.com", "instagram.com", false);
            }
        }
        return str2;
    }

    public static final boolean f(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        AbstractC1554i.k();
        return context.getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).getBoolean("limitEventUsage", false);
    }

    public static final synchronized boolean g() {
        return s;
    }

    public static final void h(y behavior) {
        Intrinsics.checkNotNullParameter(behavior, "behavior");
        synchronized (b) {
        }
    }

    public static final void i(Context context) throws PackageManager.NameNotFoundException {
        if (context == null) {
            return;
        }
        try {
            ApplicationInfo applicationInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "try {\n                co…     return\n            }");
            if (applicationInfo.metaData == null) {
                return;
            }
            if (d == null) {
                Object obj = applicationInfo.metaData.get("com.facebook.sdk.ApplicationId");
                if (obj instanceof String) {
                    String str = (String) obj;
                    Locale locale = Locale.ROOT;
                    if (kotlin.text.D.r(androidx.compose.ui.node.B.k(locale, "ROOT", str, locale, "this as java.lang.String).toLowerCase(locale)"), "fb", false)) {
                        String strSubstring = str.substring(2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
                        d = strSubstring;
                    } else {
                        d = str;
                    }
                } else if (obj instanceof Number) {
                    throw new FacebookException("App Ids cannot be directly placed in the manifest.They must be prefixed by 'fb' or be placed in the string resource file.");
                }
            }
            if (e == null) {
                e = applicationInfo.metaData.getString("com.facebook.sdk.ApplicationName");
            }
            if (f == null) {
                f = applicationInfo.metaData.getString("com.facebook.sdk.ClientToken");
            }
            if (i == 64206) {
                i = applicationInfo.metaData.getInt("com.facebook.sdk.CallbackOffset", 64206);
            }
            if (g == null) {
                g = Boolean.valueOf(applicationInfo.metaData.getBoolean("com.facebook.sdk.CodelessDebugLogEnabled", false));
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
    }

    public static final synchronized void j(Context applicationContext) {
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        k(applicationContext, null);
    }

    public static final synchronized void k(Context context, com.google.android.material.search.a aVar) {
        ActivityInfo activityInfo;
        boolean zA;
        boolean z = false;
        int i2 = 1;
        synchronized (o.class) {
            try {
                Intrinsics.checkNotNullParameter(context, "applicationContext");
                if (o.get()) {
                    if (aVar != null) {
                        ((Function0) aVar.b).invoke();
                    }
                    return;
                }
                Intrinsics.checkNotNullParameter(context, "context");
                PackageManager packageManager = context.getPackageManager();
                if (packageManager != null) {
                    try {
                        activityInfo = packageManager.getActivityInfo(new ComponentName(context, "com.facebook.FacebookActivity"), 1);
                    } catch (PackageManager.NameNotFoundException unused) {
                    }
                } else {
                    activityInfo = null;
                }
                if (activityInfo == null) {
                    Log.w("com.facebook.internal.i", "FacebookActivity is not declared in the AndroidManifest.xml. If you are using the facebook-common module or dependent modules please add com.facebook.FacebookActivity to your AndroidManifest.xml file. See https://developers.facebook.com/docs/android/getting-started for more info.");
                }
                Intrinsics.checkNotNullParameter(context, "context");
                if (context.checkCallingOrSelfPermission("android.permission.INTERNET") == -1) {
                    Log.w("com.facebook.internal.i", "No internet permissions granted for the app, please add <uses-permission android:name=\"android.permission.INTERNET\" /> to your AndroidManifest.xml.");
                }
                Context applicationContext = context.getApplicationContext();
                Intrinsics.checkNotNullExpressionValue(applicationContext, "applicationContext.applicationContext");
                h = applicationContext;
                I.a(context);
                Context context2 = h;
                if (context2 == null) {
                    Intrinsics.m("applicationContext");
                    throw null;
                }
                i(context2);
                String str = d;
                if (str == null || str.length() == 0) {
                    throw new FacebookException("A valid Facebook app id must be set in the AndroidManifest.xml or set by calling FacebookSdk.setApplicationId before initializing the sdk.");
                }
                String str2 = f;
                if (str2 == null || str2.length() == 0) {
                    throw new FacebookException("A valid Facebook app client token must be set in the AndroidManifest.xml or set by calling FacebookSdk.setClientToken before initializing the sdk.");
                }
                o.set(true);
                B b2 = B.a;
                if (com.facebook.internal.instrument.crashshield.a.b(B.class)) {
                    zA = false;
                } else {
                    try {
                        B.a.e();
                        zA = B.d.a();
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(B.class, th);
                    }
                }
                if (zA) {
                    s = true;
                }
                Context context3 = h;
                if (context3 == null) {
                    Intrinsics.m("applicationContext");
                    throw null;
                }
                if ((context3 instanceof Application) && B.c()) {
                    Context context4 = h;
                    if (context4 == null) {
                        Intrinsics.m("applicationContext");
                        throw null;
                    }
                    com.facebook.appevents.internal.c.c((Application) context4, d);
                } else {
                    com.facebook.appevents.iap.p.l();
                }
                com.facebook.appevents.internal.h hVarA = com.facebook.appevents.internal.h.b.a();
                if (hVarA != null) {
                    Context context5 = h;
                    if (context5 == null) {
                        Intrinsics.m("applicationContext");
                        throw null;
                    }
                    Application application = (Application) context5;
                    if (!com.facebook.internal.instrument.crashshield.a.b(hVarA)) {
                        try {
                            Intrinsics.checkNotNullParameter(application, "application");
                            application.registerActivityLifecycleCallbacks(new com.facebook.appevents.internal.b(i2));
                        } catch (Throwable th2) {
                            com.facebook.internal.instrument.crashshield.a.a(hVarA, th2);
                        }
                    }
                }
                com.facebook.internal.y.d();
                C.k();
                C1549d c1549d = C1549d.c;
                Context context6 = h;
                if (context6 == null) {
                    Intrinsics.m("applicationContext");
                    throw null;
                }
                J.s(context6);
                m callable = new m();
                Intrinsics.checkNotNullParameter(callable, "callable");
                com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(8, z);
                aVar2.c = new CountDownLatch(1);
                c().execute(new FutureTask(new androidx.work.impl.A(2, aVar2, callable)));
                C1563s.a(new s0(21), EnumC1562q.Instrument);
                C1563s.a(new s0(22), EnumC1562q.AppEvents);
                C1563s.a(new s0(23), EnumC1562q.ChromeCustomTabsPrefetching);
                C1563s.a(new s0(24), EnumC1562q.IgnoreAppSwitchToLoggedOut);
                C1563s.a(new s0(25), EnumC1562q.BypassAppSwitch);
                c().execute(new FutureTask(new androidx.work.impl.utils.d(aVar, 3)));
            } catch (Throwable th3) {
                throw th3;
            }
        }
    }
}
