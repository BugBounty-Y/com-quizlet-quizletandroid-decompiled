package com.facebook.appevents.codeless;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.facebook.internal.A;
import com.facebook.o;
import com.facebook.t;
import com.facebook.w;
import com.facebook.y;
import java.lang.ref.WeakReference;
import java.util.Timer;
import java.util.concurrent.RejectedExecutionException;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class k {
    public static final String e;
    public final Handler a;
    public final WeakReference b;
    public Timer c;
    public String d;

    static {
        String canonicalName = k.class.getCanonicalName();
        if (canonicalName == null) {
            canonicalName = "";
        }
        e = canonicalName;
    }

    public k(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.b = new WeakReference(activity);
        this.d = null;
        this.a = new Handler(Looper.getMainLooper());
    }

    public static final /* synthetic */ String a() {
        if (com.facebook.internal.instrument.crashshield.a.b(k.class)) {
            return null;
        }
        try {
            return e;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(k.class, th);
            return null;
        }
    }

    public final void b(t tVar, String str) {
        String str2 = e;
        if (com.facebook.internal.instrument.crashshield.a.b(this) || tVar == null) {
            return;
        }
        try {
            w wVarC = tVar.c();
            try {
                JSONObject jSONObject = wVarC.b;
                if (jSONObject == null) {
                    Log.e(str2, "Error sending UI component tree to Facebook: " + wVarC.c);
                    return;
                }
                if ("true".equals(jSONObject.optString("success"))) {
                    com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                    com.google.mlkit.common.sdkinternal.model.a.v(y.d, str2, "Successfully send UI component tree to server");
                    this.d = str;
                }
                if (jSONObject.has("is_app_indexing_enabled")) {
                    boolean z = jSONObject.getBoolean("is_app_indexing_enabled");
                    if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
                        return;
                    }
                    try {
                        d.g.set(z);
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(d.class, th);
                    }
                }
            } catch (JSONException e2) {
                Log.e(str2, "Error decoding server response.", e2);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    public final void c() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            try {
                o.c().execute(new androidx.credentials.playservices.controllers.c(21, this, new j(this, 0)));
            } catch (RejectedExecutionException e2) {
                Log.e(e, "Error scheduling indexing job", e2);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
