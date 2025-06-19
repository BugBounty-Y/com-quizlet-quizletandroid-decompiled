package com.facebook.appevents.suggestedevents;

import android.app.Activity;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.D2;
import java.io.File;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class d {
    public static final d a = new d();
    public static final AtomicBoolean b = new AtomicBoolean(false);
    public static final LinkedHashSet c = new LinkedHashSet();
    public static final LinkedHashSet d = new LinkedHashSet();

    public static final synchronized void a() {
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            return;
        }
        try {
            o.c().execute(new RunnableC0131h(16));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(d.class, th);
        }
    }

    public static final void d(Activity activity) {
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activity, "activity");
            try {
                if (b.get()) {
                    boolean z = false;
                    if (!com.facebook.internal.instrument.crashshield.a.b(a.class)) {
                        try {
                            z = a.f;
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(a.class, th);
                        }
                    }
                    if (z) {
                        if (c.isEmpty()) {
                            if (!d.isEmpty()) {
                            }
                        }
                        HashMap map = e.d;
                        D2.f(activity);
                        return;
                    }
                }
                HashMap map2 = e.d;
                D2.g(activity);
            } catch (Exception unused) {
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(d.class, th2);
        }
    }

    public final void b() {
        String str;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            v vVarK = y.k(o.b(), false);
            if (vVarK != null && (str = vVarK.k) != null) {
                c(str);
                if (c.isEmpty() && d.isEmpty()) {
                    return;
                }
                File fileD = com.facebook.appevents.ml.e.d();
                if (fileD == null) {
                    return;
                }
                a.f(fileD);
                WeakReference weakReference = com.facebook.appevents.internal.c.l;
                Activity activity = weakReference != null ? (Activity) weakReference.get() : null;
                if (activity != null) {
                    d(activity);
                }
            }
        } catch (Exception unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void c(String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.has("production_events")) {
                JSONArray jSONArray = jSONObject.getJSONArray("production_events");
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    LinkedHashSet linkedHashSet = c;
                    String string = jSONArray.getString(i);
                    Intrinsics.checkNotNullExpressionValue(string, "jsonArray.getString(i)");
                    linkedHashSet.add(string);
                }
            }
            if (jSONObject.has("eligible_for_prediction_events")) {
                JSONArray jSONArray2 = jSONObject.getJSONArray("eligible_for_prediction_events");
                int length2 = jSONArray2.length();
                for (int i2 = 0; i2 < length2; i2++) {
                    LinkedHashSet linkedHashSet2 = d;
                    String string2 = jSONArray2.getString(i2);
                    Intrinsics.checkNotNullExpressionValue(string2, "jsonArray.getString(i)");
                    linkedHashSet2.add(string2);
                }
            }
        } catch (Exception unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
