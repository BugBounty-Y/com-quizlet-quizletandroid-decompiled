package com.facebook.appevents;

import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1548c;
import com.facebook.x;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class v implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ v(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Locale locale = null;
        switch (this.a) {
            case 0:
                String value = this.b;
                if (com.facebook.internal.instrument.crashshield.a.b(w.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter("com.facebook.appevents.UserDataStore.internalUserData", "$key");
                    Intrinsics.checkNotNullParameter(value, "$value");
                    if (!w.c.get()) {
                        w.a.b();
                    }
                    SharedPreferences sharedPreferences = w.b;
                    if (sharedPreferences != null) {
                        sharedPreferences.edit().putString("com.facebook.appevents.UserDataStore.internalUserData", value).apply();
                        return;
                    } else {
                        Intrinsics.m("sharedPreferences");
                        throw null;
                    }
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(w.class, th);
                    return;
                }
            default:
                String str = this.b;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                    return;
                }
                try {
                    Bundle bundle = new Bundle();
                    C1548c c1548cB = AbstractC1554i.b(com.facebook.o.a());
                    JSONArray jSONArray = new JSONArray();
                    String str2 = Build.MODEL;
                    if (str2 == null) {
                        str2 = "";
                    }
                    jSONArray.put(str2);
                    if ((c1548cB != null ? c1548cB.a() : null) != null) {
                        jSONArray.put(c1548cB.a());
                    } else {
                        jSONArray.put("");
                    }
                    jSONArray.put("0");
                    jSONArray.put(com.facebook.appevents.internal.d.e() ? "1" : "0");
                    try {
                        locale = com.facebook.o.a().getResources().getConfiguration().locale;
                    } catch (Exception unused) {
                    }
                    if (locale == null) {
                        locale = Locale.getDefault();
                        Intrinsics.checkNotNullExpressionValue(locale, "getDefault()");
                    }
                    jSONArray.put(locale.getLanguage() + '_' + locale.getCountry());
                    String string = jSONArray.toString();
                    Intrinsics.checkNotNullExpressionValue(string, "extInfoArray.toString()");
                    bundle.putString("device_session_id", com.facebook.appevents.codeless.d.a());
                    bundle.putString("extinfo", string);
                    String str3 = com.facebook.t.j;
                    boolean z = true;
                    String str4 = String.format(Locale.US, "%s/app_indexing_session", Arrays.copyOf(new Object[]{str}, 1));
                    Intrinsics.checkNotNullExpressionValue(str4, "format(locale, format, *args)");
                    JSONObject jSONObject = new com.facebook.t(null, str4, bundle, x.b, null).c().b;
                    AtomicBoolean atomicBoolean = com.facebook.appevents.codeless.d.g;
                    if (jSONObject == null || !jSONObject.optBoolean("is_app_indexing_enabled", false)) {
                        z = false;
                    }
                    atomicBoolean.set(z);
                    if (atomicBoolean.get()) {
                        com.facebook.appevents.codeless.k kVar = com.facebook.appevents.codeless.d.d;
                        if (kVar != null) {
                            kVar.c();
                        }
                    } else {
                        com.facebook.appevents.codeless.d.e = null;
                    }
                    com.facebook.appevents.codeless.d.h = false;
                    return;
                } catch (Throwable th2) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th2);
                    return;
                }
        }
    }
}
