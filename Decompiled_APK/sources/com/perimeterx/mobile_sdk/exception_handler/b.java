package com.perimeterx.mobile_sdk.exception_handler;

import android.app.Application;
import androidx.collection.Y;
import androidx.compose.material.ripple.r;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3744v4;
import com.perimeterx.mobile_sdk.configurations.e;
import com.perimeterx.mobile_sdk.local_data.w;
import com.perimeterx.mobile_sdk.local_data.x;
import com.perimeterx.mobile_sdk.session.l;
import com.perimeterx.mobile_sdk.session.m;
import com.quizlet.data.interactor.set.c;
import java.lang.Thread;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.text.D;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b implements Thread.UncaughtExceptionHandler {
    public static final b a = new b();
    public static String b;
    public static boolean c;
    public static boolean d;
    public static boolean e;
    public static Thread.UncaughtExceptionHandler f;

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final void uncaughtException(Thread t, Throwable e2) throws JSONException {
        Intrinsics.checkNotNullParameter(t, "t");
        Intrinsics.checkNotNullParameter(e2, "e");
        if (d) {
            return;
        }
        d = true;
        Y yF = O.f(e2.getStackTrace());
        while (true) {
            if (!yF.hasNext()) {
                break;
            }
            String className = ((StackTraceElement) yF.next()).getClassName();
            Intrinsics.checkNotNullExpressionValue(className, "getClassName(...)");
            if (D.r(className, "com.perimeterx.mobile_sdk", false)) {
                HashMap map = new HashMap();
                Application application = l.b;
                if (application != null) {
                    com.perimeterx.mobile_sdk.detections.device.a aVarB = new c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(application);
                    r rVarA = AbstractC3744v4.a(application);
                    ArrayList arrayList = new ArrayList();
                    Y yF2 = O.f(e2.getStackTrace());
                    while (yF2.hasNext()) {
                        arrayList.add(((StackTraceElement) yF2.next()).toString());
                    }
                    map.put(e.c.a(), arrayList);
                    map.put(e.a.a(), e2.toString());
                    map.put(e.b.a(), String.valueOf(e2.getMessage()));
                    map.put(e.d.a(), Long.valueOf(assistantMode.refactored.a.f() / 1000));
                    String strA = e.e.a();
                    String str = b;
                    Intrinsics.d(str);
                    map.put(strA, str);
                    map.put(e.f.a(), (String) rVarA.e);
                    map.put(e.g.a(), (String) rVarA.c);
                    map.put(e.h.a(), (String) rVarA.d);
                    map.put(e.i.a(), (String) rVarA.b);
                    map.put(e.j.a(), aVarB.l);
                    map.put(e.k.a(), aVarB.i);
                }
                Intrinsics.checkNotNullParameter(map, "map");
                JSONObject jSONObject = new JSONObject();
                for (Map.Entry entry : map.entrySet()) {
                    jSONObject.putOpt((String) entry.getKey(), entry.getValue());
                }
                String string = jSONObject.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                String appId = b;
                if (appId != null) {
                    x key = x.e;
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(appId, "appId");
                    com.perimeterx.mobile_sdk.local_data.b bVar = w.c;
                    if (bVar == null) {
                        Intrinsics.m("storage");
                        throw null;
                    }
                    if (string == null) {
                        string = "";
                    }
                    bVar.c(string, key, appId);
                }
            }
        }
        Thread.UncaughtExceptionHandler uncaughtExceptionHandler = f;
        if (uncaughtExceptionHandler != null) {
            uncaughtExceptionHandler.uncaughtException(t, e2);
        }
    }
}
