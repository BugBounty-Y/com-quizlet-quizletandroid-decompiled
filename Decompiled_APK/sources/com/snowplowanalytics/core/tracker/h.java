package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.os.Looper;
import android.os.StatFs;
import android.telephony.TelephonyManager;
import com.amazon.device.ads.DtbConstants;
import java.util.Locale;
import java.util.MissingResourceException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class h extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(i iVar, int i) {
        super(0);
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        ActivityManager activityManager;
        i iVar = this.b;
        switch (this.a) {
            case 0:
                iVar.c.getClass();
                Activity context = iVar.f;
                Intrinsics.checkNotNullParameter(context, "context");
                Object systemService = context.getSystemService("activity");
                activityManager = systemService instanceof ActivityManager ? (ActivityManager) systemService : null;
                ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
                if (activityManager != null) {
                    activityManager.getMemoryInfo(memoryInfo);
                }
                return Long.valueOf(memoryInfo.availMem);
            case 1:
                iVar.c.getClass();
                return Long.valueOf(new StatFs(Environment.getDataDirectory().getPath()).getFreeBytes());
            case 2:
                iVar.c.getClass();
                Activity context2 = iVar.f;
                Intrinsics.checkNotNullParameter(context2, "context");
                return Boolean.valueOf(context2.getResources().getConfiguration().orientation == 1);
            case 3:
                iVar.c.getClass();
                try {
                    return Locale.getDefault().getISO3Language();
                } catch (MissingResourceException unused) {
                    return null;
                }
            case 4:
                iVar.c.getClass();
                Activity context3 = iVar.f;
                Intrinsics.checkNotNullParameter(context3, "context");
                if (!Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                    try {
                        Object objB = com.snowplowanalytics.core.utils.a.b("com.google.android.gms.ads.identifier.AdvertisingIdClient", "getAdvertisingIdInfo", new Class[]{Context.class}, context3);
                        Object objA = objB != null ? com.snowplowanalytics.core.utils.a.a(objB, "isLimitAdTrackingEnabled", new Object[0]) : null;
                        if (Intrinsics.b(objA instanceof Boolean ? (Boolean) objA : null, Boolean.TRUE)) {
                            return "";
                        }
                        Object objA2 = objB != null ? com.snowplowanalytics.core.utils.a.a(objB, "getId", new Object[0]) : null;
                        if (objA2 instanceof String) {
                            return (String) objA2;
                        }
                    } catch (Exception e) {
                        Intrinsics.checkNotNullExpressionValue("i", "TrackerConfiguration.TAG");
                        e.b("i", "Exception getting the Advertising ID: %s", e.toString());
                    }
                }
                return null;
            case 5:
                iVar.c.getClass();
                return DtbConstants.NATIVE_OS_NAME;
            case 6:
                iVar.c.getClass();
                String RELEASE = Build.VERSION.RELEASE;
                Intrinsics.checkNotNullExpressionValue(RELEASE, "RELEASE");
                return RELEASE;
            case 7:
                iVar.c.getClass();
                String MODEL = Build.MODEL;
                Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
                return MODEL;
            case 8:
                iVar.c.getClass();
                String MANUFACTURER = Build.MANUFACTURER;
                Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
                return MANUFACTURER;
            case 9:
                iVar.c.getClass();
                Activity context4 = iVar.f;
                Intrinsics.checkNotNullParameter(context4, "context");
                Object systemService2 = context4.getSystemService("phone");
                TelephonyManager telephonyManager = systemService2 instanceof TelephonyManager ? (TelephonyManager) systemService2 : null;
                String networkOperatorName = telephonyManager != null ? telephonyManager.getNetworkOperatorName() : null;
                if (Intrinsics.b(networkOperatorName, "")) {
                    return null;
                }
                return networkOperatorName;
            case 10:
                iVar.c.getClass();
                Activity context5 = iVar.f;
                Intrinsics.checkNotNullParameter(context5, "context");
                Object systemService3 = context5.getSystemService("activity");
                activityManager = systemService3 instanceof ActivityManager ? (ActivityManager) systemService3 : null;
                ActivityManager.MemoryInfo memoryInfo2 = new ActivityManager.MemoryInfo();
                if (activityManager != null) {
                    activityManager.getMemoryInfo(memoryInfo2);
                }
                return Long.valueOf(memoryInfo2.totalMem);
            case 11:
                iVar.c.getClass();
                return Long.valueOf(new StatFs(Environment.getDataDirectory().getPath()).getTotalBytes());
            case 12:
                iVar.c.getClass();
                Activity context6 = iVar.f;
                Intrinsics.checkNotNullParameter(context6, "context");
                int i = context6.getResources().getDisplayMetrics().widthPixels;
                int i2 = context6.getResources().getDisplayMetrics().heightPixels;
                StringBuilder sb = new StringBuilder();
                sb.append(i);
                sb.append('x');
                sb.append(i2);
                return sb.toString();
            default:
                iVar.c.getClass();
                Activity context7 = iVar.f;
                Intrinsics.checkNotNullParameter(context7, "context");
                return Float.valueOf(context7.getResources().getDisplayMetrics().density);
        }
    }
}
