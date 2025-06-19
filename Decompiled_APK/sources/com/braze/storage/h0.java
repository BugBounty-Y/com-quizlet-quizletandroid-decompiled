package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.navigation.U;
import com.braze.AbstractC1484j;
import com.braze.X;
import com.braze.managers.l0;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.braze.support.StringUtils;
import java.security.NoSuchAlgorithmException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h0 extends AbstractC1515b {
    public final com.braze.managers.g0 b;
    public final a0 c;
    public final SharedPreferences d;
    public final SharedPreferences e;
    public String f;

    public h0(Context context, com.braze.managers.g0 pushRegistrationDataProvider, a0 sdkEnablementProvider, String str, String str2) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(pushRegistrationDataProvider, "pushRegistrationDataProvider");
        Intrinsics.checkNotNullParameter(sdkEnablementProvider, "sdkEnablementProvider");
        this.b = pushRegistrationDataProvider;
        this.c = sdkEnablementProvider;
        this.f = str;
        String cacheFileSuffix = StringUtils.getCacheFileSuffix(context, str, str2);
        this.d = context.getSharedPreferences("com.appboy.storage.user_cache.v3" + cacheFileSuffix, 0);
        this.e = context.getSharedPreferences("com.braze.storage.user_cache.push_token_store" + cacheFileSuffix, 0);
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Failed to load user object json from prefs with json string: ", str);
    }

    public static final String b(String str, Object obj) {
        return "Could not write to custom attributes json object with key: [" + str + "] value: [" + obj + ']';
    }

    public static final String d() {
        return "Could not create custom attributes json object from preferences";
    }

    public static final String e() {
        return "No push token available to add to attributes object.";
    }

    public static final String f() {
        return "Couldn't add push token to outbound json";
    }

    public static final String i() {
        return "Failed to add merged custom attributes back to user object.";
    }

    public static final String k() {
        return "Push token cache cleared via sendPushTokenOnNextExport.";
    }

    public static final String m() {
        return "SDK is disabled. Not writing to user cache.";
    }

    public final JSONObject g() throws JSONException {
        JSONObject jSONObjectH = h();
        if (jSONObjectH.has("custom")) {
            try {
                JSONObject jSONObject = jSONObjectH.getJSONObject("custom");
                Intrinsics.checkNotNullExpressionValue(jSONObject, "getJSONObject(...)");
                return jSONObject;
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(13), 4, (Object) null);
            }
        }
        return new JSONObject();
    }

    public final JSONObject h() {
        String string = this.d.getString("user_cache_attributes_object", null);
        if (string == null) {
            return new JSONObject();
        }
        try {
            return new JSONObject(string);
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(string, 0), 4, (Object) null);
            return new JSONObject();
        }
    }

    public final synchronized void j() {
        try {
            try {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new B(10), 6, (Object) null);
                this.e.edit().clear().apply();
            } catch (Throwable th) {
                th = th;
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            throw th;
        }
    }

    @Override // com.braze.storage.AbstractC1515b
    /* renamed from: l, reason: merged with bridge method [inline-methods] */
    public final com.braze.models.outgoing.l c() throws JSONException {
        StringUtils.ifNonEmpty(this.f, new U(this, 5));
        JSONObject jSONObjectH = h();
        a(jSONObjectH);
        this.d.edit().clear().apply();
        return new com.braze.models.outgoing.l(jSONObjectH);
    }

    public static final String d(String str, Object obj) {
        return "Failed to write to user object json from prefs with key: [" + str + "] value: [" + obj + ']';
    }

    @Override // com.braze.storage.AbstractC1515b
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final void c(com.braze.models.outgoing.l outboundObject, boolean z) throws JSONException {
        h0 h0Var;
        Intrinsics.checkNotNullParameter(outboundObject, "outboundObject");
        JSONObject jSONObject = outboundObject.a;
        if (z) {
            if (jSONObject.has("push_token")) {
                this.e.edit().putString("push_token", jSONObject.optString("push_token")).apply();
                return;
            }
            return;
        }
        JSONObject jSONObjectH = h();
        JSONObject jSONObjectPlus = JsonUtils.plus(jSONObject, jSONObjectH);
        jSONObjectPlus.remove("push_token");
        JSONObject jSONObjectOptJSONObject = jSONObjectH.optJSONObject("custom");
        JSONObject jSONObjectOptJSONObject2 = jSONObject.optJSONObject("custom");
        try {
        } catch (JSONException e) {
            h0Var = this;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) h0Var, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(11), 4, (Object) null);
        }
        if (jSONObjectOptJSONObject != null && jSONObjectOptJSONObject2 != null) {
            jSONObjectPlus.put("custom", JsonUtils.plus(jSONObjectOptJSONObject2, jSONObjectOptJSONObject));
        } else {
            if (jSONObjectOptJSONObject == null) {
                if (jSONObjectOptJSONObject2 != null) {
                    jSONObjectPlus.put("custom", jSONObjectOptJSONObject2);
                }
                h0Var = this;
                h0Var.d.edit().putString("user_cache_attributes_object", jSONObjectPlus.toString()).apply();
            }
            jSONObjectPlus.put("custom", jSONObjectOptJSONObject);
        }
        h0Var = this;
        h0Var.d.edit().putString("user_cache_attributes_object", jSONObjectPlus.toString()).apply();
    }

    public final boolean c(JSONObject jSONObject) {
        if (this.c.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new B(12), 6, (Object) null);
            return false;
        }
        this.d.edit().putString("user_cache_attributes_object", jSONObject.toString()).apply();
        return true;
    }

    public final boolean c(String str, Object obj) throws JSONException {
        Object obj2;
        JSONObject jSONObjectH = h();
        if (obj == null) {
            try {
                obj2 = JSONObject.NULL;
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new X(str, 5, obj), 4, (Object) null);
                return false;
            }
        } else {
            obj2 = obj;
        }
        jSONObjectH.put(str, obj2);
        return c(jSONObjectH);
    }

    public final void a(JSONObject outboundJson) throws JSONException {
        Intrinsics.checkNotNullParameter(outboundJson, "outboundJson");
        try {
            String strB = ((l0) this.b).b();
            if (strB == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new B(8), 7, (Object) null);
            } else {
                if (strB.equals(this.e.getString("push_token", null))) {
                    return;
                }
                outboundJson.put("push_token", strB);
            }
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(9), 4, (Object) null);
        }
    }

    public static final Unit a(h0 h0Var, String it2) throws JSONException {
        Intrinsics.checkNotNullParameter(it2, "it");
        h0Var.c("user_id", it2);
        return Unit.a;
    }

    public final boolean a(String key, Object obj) throws JSONException {
        Object obj2;
        Intrinsics.checkNotNullParameter(key, "key");
        JSONObject jSONObjectG = g();
        if (obj == null) {
            try {
                obj2 = JSONObject.NULL;
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new X(key, 6, obj), 4, (Object) null);
                return false;
            }
        } else {
            obj2 = obj;
        }
        jSONObjectG.put(key, obj2);
        return c("custom", jSONObjectG);
    }
}
