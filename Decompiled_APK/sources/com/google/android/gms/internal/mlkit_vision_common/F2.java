package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class F2 {
    public static final void a(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-259081107);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.material3.Z1.e(nVar2, com.quizlet.themes.m.m, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i(), c0814p, 6, 0);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar, i, 3);
        }
    }

    public static final com.facebook.internal.instrument.c b(String str, String str2) throws PackageManager.NameNotFoundException {
        com.facebook.internal.instrument.c cVar = new com.facebook.internal.instrument.c();
        cVar.b = com.facebook.internal.instrument.a.c;
        Context contextA = com.facebook.o.a();
        String str3 = null;
        try {
            PackageInfo packageInfo = contextA.getPackageManager().getPackageInfo(contextA.getPackageName(), 0);
            if (packageInfo != null) {
                str3 = packageInfo.versionName;
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
        cVar.d = str3;
        cVar.e = str;
        cVar.f = str2;
        Long lValueOf = Long.valueOf(System.currentTimeMillis() / 1000);
        cVar.g = lValueOf;
        StringBuffer stringBuffer = new StringBuffer("anr_log_");
        stringBuffer.append(String.valueOf(lValueOf));
        stringBuffer.append(".json");
        String string = stringBuffer.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuffer()\n         …)\n            .toString()");
        cVar.a = string;
        return cVar;
    }

    public static final com.facebook.internal.instrument.c c(Throwable th, com.facebook.internal.instrument.a t) throws PackageManager.NameNotFoundException {
        PackageInfo packageInfo;
        Intrinsics.checkNotNullParameter(t, "t");
        com.facebook.internal.instrument.c cVar = new com.facebook.internal.instrument.c();
        cVar.b = t;
        Context contextA = com.facebook.o.a();
        String string = null;
        Throwable th2 = null;
        try {
            packageInfo = contextA.getPackageManager().getPackageInfo(contextA.getPackageName(), 0);
        } catch (PackageManager.NameNotFoundException unused) {
        }
        String str = packageInfo == null ? null : packageInfo.versionName;
        cVar.d = str;
        cVar.e = th == null ? null : th.getCause() == null ? th.toString() : String.valueOf(th.getCause());
        if (th != null) {
            JSONArray jSONArray = new JSONArray();
            while (th != null && th != th2) {
                StackTraceElement[] stackTrace = th.getStackTrace();
                Intrinsics.checkNotNullExpressionValue(stackTrace, "t.stackTrace");
                for (StackTraceElement stackTraceElement : stackTrace) {
                    jSONArray.put(stackTraceElement.toString());
                }
                th2 = th;
                th = th.getCause();
            }
            string = jSONArray.toString();
        }
        cVar.f = string;
        Long lValueOf = Long.valueOf(System.currentTimeMillis() / 1000);
        cVar.g = lValueOf;
        StringBuffer stringBuffer = new StringBuffer();
        int iOrdinal = t.ordinal();
        stringBuffer.append(iOrdinal != 1 ? iOrdinal != 2 ? iOrdinal != 3 ? iOrdinal != 4 ? iOrdinal != 5 ? "Unknown" : "thread_check_log_" : "shield_log_" : "crash_log_" : "anr_log_" : "analysis_log_");
        stringBuffer.append(String.valueOf(lValueOf));
        stringBuffer.append(".json");
        String string2 = stringBuffer.toString();
        Intrinsics.checkNotNullExpressionValue(string2, "StringBuffer().append(t.…ppend(\".json\").toString()");
        cVar.a = string2;
        return cVar;
    }

    public static final com.facebook.internal.instrument.c d(File file) {
        Intrinsics.checkNotNullParameter(file, "file");
        com.facebook.internal.instrument.c cVar = new com.facebook.internal.instrument.c();
        String name = file.getName();
        Intrinsics.checkNotNullExpressionValue(name, "file.name");
        cVar.a = name;
        cVar.b = kotlin.text.D.r(name, "crash_log_", false) ? com.facebook.internal.instrument.a.d : kotlin.text.D.r(name, "shield_log_", false) ? com.facebook.internal.instrument.a.e : kotlin.text.D.r(name, "thread_check_log_", false) ? com.facebook.internal.instrument.a.f : kotlin.text.D.r(name, "analysis_log_", false) ? com.facebook.internal.instrument.a.b : kotlin.text.D.r(name, "anr_log_", false) ? com.facebook.internal.instrument.a.c : com.facebook.internal.instrument.a.a;
        JSONObject jSONObjectG = G2.g(name);
        if (jSONObjectG != null) {
            cVar.g = Long.valueOf(jSONObjectG.optLong("timestamp", 0L));
            cVar.d = jSONObjectG.optString("app_version", null);
            cVar.e = jSONObjectG.optString("reason", null);
            cVar.f = jSONObjectG.optString("callstack", null);
            cVar.c = jSONObjectG.optJSONArray("feature_names");
        }
        return cVar;
    }
}
