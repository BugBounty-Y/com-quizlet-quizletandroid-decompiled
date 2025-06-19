package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import com.perimeterx.mobile_sdk.PerimeterX;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.v4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3744v4 {
    public static final /* synthetic */ int a = 0;

    public static androidx.compose.material.ripple.r a(Application context) {
        String appName;
        com.google.android.gms.internal.instantapps.a aVar;
        Intrinsics.checkNotNullParameter(context, "context");
        String packageName = context.getApplicationContext().getPackageName();
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        int i = applicationInfo.labelRes;
        if (i == 0) {
            appName = applicationInfo.nonLocalizedLabel.toString();
        } else {
            appName = context.getString(i);
            Intrinsics.checkNotNullExpressionValue(appName, "getString(...)");
        }
        String appVersion = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        Intrinsics.checkNotNullExpressionValue(appVersion, "versionName");
        String pxSDKVersion = PerimeterX.INSTANCE.sdkVersion();
        synchronized (com.google.android.gms.internal.instantapps.a.class) {
            Context applicationContext = context.getApplicationContext();
            Context applicationContext2 = context;
            if (applicationContext != null) {
                applicationContext2 = context.getApplicationContext();
            }
            com.google.android.gms.internal.instantapps.a aVar2 = com.google.android.gms.internal.instantapps.a.c;
            if (aVar2 == null || ((Context) aVar2.b) != applicationContext2) {
                com.google.android.gms.internal.instantapps.a.c = new com.google.android.gms.internal.instantapps.a(applicationContext2, 0);
            }
            aVar = com.google.android.gms.internal.instantapps.a.c;
        }
        boolean zIsInstantApp = ((Context) aVar.b).getPackageManager().isInstantApp(((Context) aVar.b).getPackageName());
        Intrinsics.d(packageName);
        Intrinsics.checkNotNullParameter(packageName, "packageName");
        Intrinsics.checkNotNullParameter(appName, "appName");
        Intrinsics.checkNotNullParameter(appVersion, "appVersion");
        Intrinsics.checkNotNullParameter(pxSDKVersion, "pxSDKVersion");
        androidx.compose.material.ripple.r rVar = new androidx.compose.material.ripple.r();
        rVar.b = packageName;
        rVar.c = appName;
        rVar.d = appVersion;
        rVar.e = pxSDKVersion;
        rVar.a = zIsInstantApp;
        return rVar;
    }
}
