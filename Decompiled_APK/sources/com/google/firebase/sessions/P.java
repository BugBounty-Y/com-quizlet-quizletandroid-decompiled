package com.google.firebase.sessions;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class P {
    public static final P a = new P();
    public static final androidx.webkit.internal.p b;

    static {
        com.google.firebase.encoders.json.d dVar = new com.google.firebase.encoders.json.d();
        dVar.g(O.class, C3985g.a);
        dVar.g(Y.class, C3986h.a);
        dVar.g(C3989k.class, C3983e.a);
        dVar.g(C3980b.class, C3982d.a);
        dVar.g(C3979a.class, C3981c.a);
        dVar.g(D.class, C3984f.a);
        dVar.d = true;
        androidx.webkit.internal.p pVar = new androidx.webkit.internal.p(dVar, 25);
        Intrinsics.checkNotNullExpressionValue(pVar, "JsonDataEncoderBuilder()…lues(true)\n      .build()");
        b = pVar;
    }

    public static C3980b a(com.google.firebase.h firebaseApp) throws PackageManager.NameNotFoundException {
        Object next;
        String strH;
        Intrinsics.checkNotNullParameter(firebaseApp, "firebaseApp");
        firebaseApp.a();
        Context context = firebaseApp.a;
        Intrinsics.checkNotNullExpressionValue(context, "firebaseApp.applicationContext");
        String packageName = context.getPackageName();
        PackageInfo packageInfo = context.getPackageManager().getPackageInfo(packageName, 0);
        String strValueOf = Build.VERSION.SDK_INT >= 28 ? String.valueOf(packageInfo.getLongVersionCode()) : String.valueOf(packageInfo.versionCode);
        firebaseApp.a();
        String str = firebaseApp.c.b;
        Intrinsics.checkNotNullExpressionValue(str, "firebaseApp.options.applicationId");
        String MODEL = Build.MODEL;
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
        String RELEASE = Build.VERSION.RELEASE;
        Intrinsics.checkNotNullExpressionValue(RELEASE, "RELEASE");
        Intrinsics.checkNotNullExpressionValue(packageName, "packageName");
        String str2 = packageInfo.versionName;
        if (str2 == null) {
            str2 = strValueOf;
        }
        String MANUFACTURER = Build.MANUFACTURER;
        Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
        firebaseApp.a();
        Intrinsics.checkNotNullExpressionValue(context, "firebaseApp.applicationContext");
        Intrinsics.checkNotNullParameter(context, "context");
        int iMyPid = Process.myPid();
        Iterator it2 = AbstractC3997t.a(context).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((D) next).b == iMyPid) {
                break;
            }
        }
        D d = (D) next;
        if (d == null) {
            int i = Build.VERSION.SDK_INT;
            if (i > 33) {
                strH = Process.myProcessName();
                Intrinsics.checkNotNullExpressionValue(strH, "myProcessName()");
            } else if ((i < 28 || (strH = Application.getProcessName()) == null) && (strH = com.google.android.gms.common.util.c.h()) == null) {
                strH = "";
            }
            d = new D(iMyPid, 0, strH, false);
        }
        firebaseApp.a();
        Intrinsics.checkNotNullExpressionValue(context, "firebaseApp.applicationContext");
        return new C3980b(str, new C3979a(packageName, str2, strValueOf, d, AbstractC3997t.a(context)));
    }
}
