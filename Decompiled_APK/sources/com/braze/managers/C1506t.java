package com.braze.managers;

import android.app.ActivityManager;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.telephony.TelephonyManager;
import com.braze.AbstractC1476b;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.support.BrazeLogger;
import java.util.Locale;
import java.util.TimeZone;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.braze.managers.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1506t implements d0 {
    public static final C1505s f = new C1505s();
    public final Context a;
    public final BrazeConfigurationProvider b;
    public final String c;
    public final SharedPreferences d;
    public PackageInfo e;

    public C1506t(Context context, BrazeConfigurationProvider configurationProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        this.a = context;
        this.b = configurationProvider;
        PackageInfo packageInfoJ = j();
        this.c = packageInfoJ != null ? packageInfoJ.versionName : null;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.managers.device_data_provider", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.d = sharedPreferences;
    }

    public static final String a(String str) {
        return AbstractC1476b.a("Unable to inspect package [", str, ']');
    }

    public static final String g() {
        return "Failed to collect background restriction information from Activity Manager";
    }

    public static final String i() {
        return "Caught exception while reading the phone carrier name.";
    }

    public final com.braze.models.outgoing.h b() {
        BrazeConfigurationProvider configurationProvider = this.b;
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        String strValueOf = String.valueOf(Build.VERSION.SDK_INT);
        String strH = h();
        String str = Build.BRAND;
        if (str == null || StringsKt.O(str)) {
            str = null;
        }
        String str2 = Build.MODEL;
        C1505s c1505s = f;
        Locale locale = Locale.getDefault();
        Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
        Intrinsics.checkNotNullParameter(locale, "locale");
        String string = locale.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        TimeZone timeZone = TimeZone.getDefault();
        Intrinsics.checkNotNullExpressionValue(timeZone, "getDefault(...)");
        String id = timeZone.getID();
        Context context = this.a;
        return new com.braze.models.outgoing.h(configurationProvider, strValueOf, strH, str, str2, string, id, c1505s.a(context, context.getResources().getConfiguration().orientation == 2), Boolean.valueOf(d()), Boolean.valueOf(f()), this.d.getString("google_ad_id", null), this.d.contains("ad_tracking_enabled") ? Boolean.valueOf(this.d.getBoolean("ad_tracking_enabled", true)) : null);
    }

    public final String c() {
        PackageInfo packageInfoJ = j();
        if (packageInfoJ == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(13), 7, (Object) null);
            return null;
        }
        int i = Build.VERSION.SDK_INT;
        return (i >= 28 ? packageInfoJ.getLongVersionCode() : i >= 28 ? androidx.arch.core.executor.d.d(packageInfoJ) : packageInfoJ.versionCode) + ".0.0.0";
    }

    public final boolean d() {
        Object systemService = this.a.getSystemService("notification");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
        return ((NotificationManager) systemService).areNotificationsEnabled();
    }

    public final boolean f() {
        if (Build.VERSION.SDK_INT < 28) {
            return false;
        }
        try {
            Object systemService = this.a.getSystemService("activity");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.ActivityManager");
            return ((ActivityManager) systemService).isBackgroundRestricted();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(11), 4, (Object) null);
            return false;
        }
    }

    public final String h() {
        try {
            Object systemService = this.a.getSystemService("phone");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.telephony.TelephonyManager");
            String networkOperatorName = ((TelephonyManager) systemService).getNetworkOperatorName();
            if (networkOperatorName != null) {
                return StringsKt.g0(networkOperatorName).toString();
            }
            return null;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(12), 4, (Object) null);
            return null;
        }
    }

    public final PackageInfo j() {
        PackageInfo packageInfo = this.e;
        if (packageInfo != null) {
            return packageInfo;
        }
        String packageName = this.a.getPackageName();
        try {
            PackageInfo packageInfo2 = Build.VERSION.SDK_INT >= 33 ? this.a.getPackageManager().getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L)) : this.a.getPackageManager().getPackageInfo(packageName, 0);
            this.e = packageInfo2;
            return packageInfo2;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(packageName, 12), 4, (Object) null);
            ApplicationInfo applicationInfo = this.a.getApplicationInfo();
            PackageInfo packageArchiveInfo = Build.VERSION.SDK_INT >= 33 ? this.a.getPackageManager().getPackageArchiveInfo(applicationInfo.sourceDir, PackageManager.PackageInfoFlags.of(0L)) : this.a.getPackageManager().getPackageArchiveInfo(applicationInfo.sourceDir, 0);
            this.e = packageArchiveInfo;
            return packageArchiveInfo;
        }
    }

    public static final String a() {
        return "App version code could not be read. Returning null";
    }
}
