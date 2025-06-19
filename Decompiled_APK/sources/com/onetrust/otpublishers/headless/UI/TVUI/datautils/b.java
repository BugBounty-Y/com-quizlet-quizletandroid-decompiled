package com.onetrust.otpublishers.headless.UI.TVUI.datautils;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.constraintlayout.motion.widget.n;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public static b w;
    public JSONObject a;
    public boolean o;
    public boolean s;
    public boolean t;
    public String b = "On";
    public String c = "Off";
    public String d = "SUB-CATEGORIES";
    public String e = "";
    public String f = "";
    public String g = "";
    public String h = "";
    public String i = "";
    public String j = "";
    public String k = "";
    public String l = "";
    public String m = "";
    public String n = "";
    public String p = "";
    public String q = "";
    public boolean r = true;
    public n u = new n();
    public n v = new n();

    public static synchronized b a() {
        try {
            if (w == null) {
                w = new b();
            }
        } catch (Throwable th) {
            throw th;
        }
        return w;
    }

    public final void b(Context context) {
        boolean z;
        f fVar;
        boolean z2;
        JSONObject jSONObjectOptJSONObject;
        try {
            JSONObject jSONObject = this.a;
            if (jSONObject == null) {
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                    fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z = true;
                } else {
                    z = false;
                    fVar = null;
                }
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                f fVar2 = fVar;
                if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                    String string = sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", "");
                    StringBuilder sb = new StringBuilder("com.onetrust.otpublishers.headless.preference.OTT_USER_");
                    z2 = z;
                    sb.append(new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(string));
                    SharedPreferences sharedPreferences3 = context.getSharedPreferences(sb.toString(), 0);
                    sharedPreferences2.edit();
                    sharedPreferences3.edit();
                } else {
                    z2 = z;
                }
                SharedPreferences sharedPreferences4 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                    SharedPreferences sharedPreferences5 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences4.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                    sharedPreferences4.edit();
                    sharedPreferences5.edit();
                }
                String string2 = (z2 ? fVar2 : sharedPreferences).getString("OT_OTT_DATA", null);
                jSONObject = com.onetrust.otpublishers.headless.Internal.a.j(string2) ? null : new JSONObject(string2);
            }
            this.a = jSONObject;
            if (retrofit2.adapter.rxjava3.d.o(jSONObject)) {
                return;
            }
            JSONObject jSONObjectOptJSONObject2 = this.a.optJSONObject("preferenceCenterData");
            if (jSONObjectOptJSONObject2 != null && jSONObjectOptJSONObject2.has("purposeList") && (jSONObjectOptJSONObject = jSONObjectOptJSONObject2.optJSONObject("purposeList")) != null) {
                this.b = jSONObjectOptJSONObject.optString("ActiveText");
                this.c = jSONObjectOptJSONObject.optString("InactiveText");
                this.d = jSONObjectOptJSONObject.optString("SubCategoryHeaderText");
                this.o = jSONObjectOptJSONObject.optBoolean("InteractionChoiceIsConsentShow");
                OTLogger.c("OTTDataParser", 3, "isInteractionChoiceIsConsent: " + this.o);
                this.p = jSONObjectOptJSONObject.optString("InteractionChoiceText");
            }
            JSONObject jSONObject2 = this.a.getJSONObject("bannerData");
            d(jSONObject2, true);
            c(jSONObject2);
            JSONObject jSONObject3 = this.a.getJSONObject("preferenceCenterData");
            d(jSONObject3, false);
            if (jSONObject3.has("menu")) {
                JSONObject jSONObject4 = jSONObject3.getJSONObject("menu");
                this.i = jSONObject4.optString("color");
                this.j = jSONObject4.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
                this.k = jSONObject4.optString("focusColor");
                this.l = jSONObject4.optString("focusTextColor");
                this.m = jSONObject4.optString("activeColor");
                this.n = jSONObject4.optString("activeTextColor");
            }
            JSONObject jSONObject5 = this.a;
            if (jSONObject5.has("vendorListData")) {
                JSONObject jSONObject6 = jSONObject5.getJSONObject("vendorListData");
                if (jSONObject6.has(OTVendorListMode.GENERAL)) {
                    JSONObject jSONObject7 = jSONObject6.getJSONObject(OTVendorListMode.GENERAL);
                    if (jSONObject7.has("showFilterIcon")) {
                        this.r = jSONObject7.getBoolean("showFilterIcon");
                    }
                }
            }
        } catch (JSONException e) {
            Z.p("Error while parsing OTT data, error: ", e, "OneTrust", 6);
        }
    }

    public final void c(JSONObject jSONObject) throws JSONException {
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BUTTONS)) {
            JSONObject jSONObject2 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_BUTTONS);
            if (jSONObject2.has(OTUXParamsKeys.OT_UX_SHOW_PREFERENCES)) {
                JSONObject jSONObject3 = jSONObject2.getJSONObject(OTUXParamsKeys.OT_UX_SHOW_PREFERENCES);
                n nVar = new n();
                if (jSONObject3.has("color")) {
                    nVar.e = jSONObject3.getString("color");
                }
                if (jSONObject3.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
                    nVar.f = jSONObject3.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
                }
                this.v = nVar;
            }
            if (jSONObject2.has(OTUXParamsKeys.OT_UX_LINK_VENDOR_LIST)) {
                JSONObject jSONObject4 = jSONObject2.getJSONObject(OTUXParamsKeys.OT_UX_LINK_VENDOR_LIST);
                n nVar2 = new n();
                if (jSONObject4.has("color")) {
                    nVar2.e = jSONObject4.getString("color");
                }
                if (jSONObject4.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
                    nVar2.f = jSONObject4.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
                }
                this.u = nVar2;
            }
        }
    }

    public final void d(JSONObject jSONObject, boolean z) throws JSONException {
        if (jSONObject.has(OTVendorListMode.GENERAL)) {
            JSONObject jSONObject2 = jSONObject.getJSONObject(OTVendorListMode.GENERAL);
            if (!z) {
                this.g = jSONObject2.optString("buttonFocusColor");
                this.h = jSONObject2.optString("buttonFocusTextColor");
                this.t = jSONObject2.optBoolean("buttonBorderShow");
            } else {
                this.e = jSONObject2.optString("buttonFocusColor");
                this.f = jSONObject2.optString("buttonFocusTextColor");
                this.q = jSONObject2.optString("layout", "right");
                this.s = jSONObject2.optBoolean("buttonBorderShow");
            }
        }
    }
}
