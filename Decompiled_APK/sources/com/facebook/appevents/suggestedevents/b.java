package com.facebook.appevents.suggestedevents;

import android.content.SharedPreferences;
import android.view.View;
import com.facebook.appevents.codeless.internal.g;
import com.facebook.internal.J;
import com.facebook.o;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b {
    public static SharedPreferences c;
    public static final b a = new b();
    public static final LinkedHashMap b = new LinkedHashMap();
    public static final AtomicBoolean d = new AtomicBoolean(false);

    public static final void a(String pathID, String predictedEvent) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(pathID, "pathID");
            Intrinsics.checkNotNullParameter(predictedEvent, "predictedEvent");
            if (!d.get()) {
                a.c();
            }
            LinkedHashMap linkedHashMap = b;
            linkedHashMap.put(pathID, predictedEvent);
            SharedPreferences sharedPreferences = c;
            if (sharedPreferences != null) {
                sharedPreferences.edit().putString("SUGGESTED_EVENTS_HISTORY", J.H(V.l(linkedHashMap))).apply();
            } else {
                Intrinsics.m("shardPreferences");
                throw null;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
        }
    }

    public static final String b(View view, String text) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            Intrinsics.checkNotNullParameter(text, "text");
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("text", text);
                JSONArray jSONArray = new JSONArray();
                while (view != null) {
                    jSONArray.put(view.getClass().getSimpleName());
                    view = g.h(view);
                }
                jSONObject.put("classname", jSONArray);
            } catch (JSONException unused) {
            }
            return J.O(jSONObject.toString());
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
            return null;
        }
    }

    public final void c() {
        String str = "";
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            AtomicBoolean atomicBoolean = d;
            if (atomicBoolean.get()) {
                return;
            }
            SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.internal.SUGGESTED_EVENTS_HISTORY", 0);
            Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext()\n…RE, Context.MODE_PRIVATE)");
            c = sharedPreferences;
            LinkedHashMap linkedHashMap = b;
            if (sharedPreferences == null) {
                Intrinsics.m("shardPreferences");
                throw null;
            }
            String string = sharedPreferences.getString("SUGGESTED_EVENTS_HISTORY", "");
            if (string != null) {
                str = string;
            }
            linkedHashMap.putAll(J.G(str));
            atomicBoolean.set(true);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
