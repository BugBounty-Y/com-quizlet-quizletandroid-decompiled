package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import android.content.res.Resources;
import android.os.Build;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.WindowManager;
import android.view.WindowMetrics;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l {
    public final HashMap a;

    public l(Activity context, com.snowplowanalytics.snowplow.configuration.h hVar) {
        DisplayMetrics displayMetrics;
        com.snowplowanalytics.snowplow.util.b bVar;
        Intrinsics.checkNotNullParameter(context, "context");
        HashMap map = new HashMap();
        this.a = map;
        String id = Calendar.getInstance().getTimeZone().getID();
        if (id != null) {
            map.put("tz", id);
        }
        String displayLanguage = Locale.getDefault().getDisplayLanguage();
        if (displayLanguage != null) {
            map.put("lang", displayLanguage);
        }
        if (Intrinsics.b(Boolean.valueOf(hVar.j()), Boolean.TRUE)) {
            a(new com.snowplowanalytics.snowplow.util.b(context.getResources().getDisplayMetrics().widthPixels, context.getResources().getDisplayMetrics().heightPixels));
        } else {
            try {
                if (Build.VERSION.SDK_INT >= 30) {
                    WindowMetrics currentWindowMetrics = ((WindowManager) context.getSystemService(WindowManager.class)).getCurrentWindowMetrics();
                    Intrinsics.checkNotNullExpressionValue(currentWindowMetrics, "context.getSystemService…ava).currentWindowMetrics");
                    bVar = new com.snowplowanalytics.snowplow.util.b(currentWindowMetrics.getBounds().width(), currentWindowMetrics.getBounds().height());
                } else {
                    Object systemService = context.getSystemService("window");
                    WindowManager windowManager = systemService instanceof WindowManager ? (WindowManager) systemService : null;
                    Display defaultDisplay = windowManager != null ? windowManager.getDefaultDisplay() : null;
                    if (defaultDisplay != null) {
                        displayMetrics = new DisplayMetrics();
                        defaultDisplay.getRealMetrics(displayMetrics);
                    } else {
                        displayMetrics = Resources.getSystem().getDisplayMetrics();
                    }
                    bVar = new com.snowplowanalytics.snowplow.util.b(displayMetrics.widthPixels, displayMetrics.heightPixels);
                }
                a(bVar);
            } catch (Throwable unused) {
                Intrinsics.checkNotNullExpressionValue("l", "TAG");
                e.b("l", "Failed to set default screen resolution.", new Object[0]);
            }
        }
        String strK = hVar.k();
        if (strK != null) {
            this.a.put("uid", strK);
        }
        String strE = hVar.e();
        if (strE != null) {
            this.a.put("tnuid", strE);
        }
        String strB = hVar.b();
        if (strB != null) {
            this.a.put("duid", strB);
        }
        String strL = hVar.l();
        if (strL != null) {
            this.a.put("ua", strL);
        }
        String strC = hVar.c();
        if (strC != null) {
            this.a.put("ip", strC);
        }
        String strH = hVar.h();
        if (strH != null) {
            this.a.put("tz", strH);
        }
        String strD = hVar.d();
        if (strD != null) {
            this.a.put("lang", strD);
        }
        com.snowplowanalytics.snowplow.util.b bVarF = hVar.f();
        if (bVarF != null) {
            a(bVarF);
        }
        com.snowplowanalytics.snowplow.util.b bVarG = hVar.g();
        if (bVarG != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(bVarG.a);
            sb.append('x');
            sb.append(bVarG.b);
            this.a.put("vp", sb.toString());
        }
        Integer numA = hVar.a();
        if (numA != null) {
            this.a.put("cd", Integer.valueOf(numA.intValue()).toString());
        }
        Intrinsics.checkNotNullExpressionValue("l", "TAG");
        e.e("l", "Subject created successfully.", new Object[0]);
    }

    public final void a(com.snowplowanalytics.snowplow.util.b bVar) {
        StringBuilder sb = new StringBuilder();
        sb.append(bVar.a);
        sb.append('x');
        sb.append(bVar.b);
        this.a.put("res", sb.toString());
    }
}
