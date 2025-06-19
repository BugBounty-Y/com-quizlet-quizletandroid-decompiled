package com.braze.models.outgoing;

import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.enums.DeviceKey;
import com.braze.models.IPutIntoJson;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h implements IPutIntoJson, com.braze.models.k {
    public static final g n = new g();
    public final BrazeConfigurationProvider a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final Boolean i;
    public final Boolean j;
    public final String k;
    public final Boolean l;
    public boolean m;

    public h(BrazeConfigurationProvider configurationProvider, String str, String str2, String str3, String str4, String str5, String str6, String str7, Boolean bool, Boolean bool2, String str8, Boolean bool3) {
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        this.a = configurationProvider;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.i = bool;
        this.j = bool2;
        this.k = str8;
        this.l = bool3;
    }

    public static final String b() {
        return "Caught exception creating device Json.";
    }

    @Override // com.braze.models.k
    public final boolean isEmpty() {
        return forJsonPut().length() == 0;
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() {
        JSONObject jSONObject = new JSONObject();
        try {
            g gVar = n;
            gVar.a(this.a, jSONObject, DeviceKey.ANDROID_VERSION, this.b);
            gVar.a(this.a, jSONObject, DeviceKey.CARRIER, this.c);
            gVar.a(this.a, jSONObject, DeviceKey.BRAND, this.d);
            gVar.a(this.a, jSONObject, DeviceKey.MODEL, this.e);
            gVar.a(this.a, jSONObject, DeviceKey.RESOLUTION, this.h);
            gVar.a(this.a, jSONObject, DeviceKey.LOCALE, this.f);
            gVar.a(this.a, jSONObject, DeviceKey.NOTIFICATIONS_ENABLED, this.i);
            gVar.a(this.a, jSONObject, DeviceKey.IS_BACKGROUND_RESTRICTED, this.j);
            String str = this.k;
            if (str != null && !StringsKt.O(str)) {
                gVar.a(this.a, jSONObject, DeviceKey.GOOGLE_ADVERTISING_ID, this.k);
            }
            Boolean bool = this.l;
            if (bool != null) {
                gVar.a(this.a, jSONObject, DeviceKey.AD_TRACKING_ENABLED, bool);
            }
            String str2 = this.g;
            if (str2 != null && !StringsKt.O(str2)) {
                gVar.a(this.a, jSONObject, DeviceKey.TIMEZONE, this.g);
                return jSONObject;
            }
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new a(8), 4, (Object) null);
        }
        return jSONObject;
    }
}
