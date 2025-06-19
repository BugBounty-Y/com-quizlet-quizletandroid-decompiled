package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTBroadcastServiceKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class k {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;
    public final retrofit2.adapter.rxjava3.d b = new retrofit2.adapter.rxjava3.d(21);
    public final Context c;
    public JSONObject d;
    public JSONObject e;
    public JSONObject f;

    public k(@NonNull Context context) {
        this.c = context;
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        e();
    }

    public static void i(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        String strOptString;
        if (jSONObject2.has(str)) {
            jSONObject.put("userConsentStatus", jSONObject2.optJSONObject(str).optString("userConsentStatus"));
            strOptString = jSONObject2.optJSONObject(str).optString("transactionType");
        } else {
            strOptString = "OPT_OUT";
            jSONObject.put("userConsentStatus", "OPT_OUT");
        }
        jSONObject.put("transactionType", strOptString);
    }

    public final int a(String str, String str2) {
        int iD = U.d(str.trim() + str2.trim(), this.f);
        OTLogger.c("UCPurposesDataHandler", 4, "UCP: Consent Status for Topic id " + str + " : " + iD);
        return iD;
    }

    public final int b(String str, String str2, String str3) {
        int iD = U.d(str.trim() + str2.trim() + str3.trim(), this.e);
        OTLogger.c("UCPurposesDataHandler", 4, "UCP: Consent Status for Custom Preference Options id " + str + " : " + iD);
        return iD;
    }

    public final JSONArray c(String str) {
        String string = this.a.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_SERVER_DATA", "");
        JSONArray jSONArray = new JSONArray();
        try {
            JSONObject jSONObject = new JSONObject(string);
            for (int i = 0; i < jSONObject.length(); i++) {
                JSONObject jSONObject2 = jSONObject.getJSONObject(jSONObject.names().get(i).toString());
                if (str.equals(jSONObject2.optString("purposeId"))) {
                    jSONArray.put(jSONObject2);
                }
            }
        } catch (JSONException e) {
            Z.p("Error in fetching CP data by purpose  :", e, "UCPurposesDataHandler", 6);
        }
        OTLogger.c("UCPurposesDataHandler", 3, "Custom Prefs by PurposeId :" + jSONArray);
        return jSONArray;
    }

    public final JSONArray d(JSONArray jSONArray, String str, JSONObject jSONObject, JSONArray jSONArray2, int i) throws JSONException {
        JSONObject jSONObject2 = jSONObject.getJSONObject(jSONObject.names().get(i).toString());
        OTLogger.c("UCPurposesDataHandler", 3, "purposeObject :" + jSONObject2);
        String string = jSONObject.names().get(i).toString();
        JSONArray jSONArrayS = s(string);
        JSONArray jSONArray3 = new JSONArray();
        JSONArray jSONArray4 = new JSONArray();
        JSONObject jSONObject3 = new JSONObject();
        for (int i2 = 0; i2 < jSONArrayS.length(); i2++) {
            JSONObject jSONObject4 = jSONArrayS.getJSONObject(i2);
            if (string.equals(jSONObject4.optString("purposeId"))) {
                jSONObject3.put("name", str);
                jSONArray4.put(jSONObject4);
                jSONObject3.put("options", jSONArray4);
            } else {
                JSONObject jSONObject5 = new JSONObject();
                JSONArray jSONArray5 = new JSONArray();
                jSONObject2.put("topics", jSONArray5);
                jSONObject3 = jSONObject5;
                jSONArray3 = jSONArray5;
            }
        }
        if (jSONObject3.length() > 0) {
            jSONArray3.put(jSONObject3);
        }
        jSONObject2.put("topics", jSONArray3);
        JSONArray jSONArrayC = c(string);
        JSONArray jSONArray6 = new JSONArray();
        JSONArray jSONArrayN = jSONArray2;
        for (int i3 = 0; i3 < jSONArrayC.length(); i3++) {
            JSONObject jSONObject6 = jSONArrayC.getJSONObject(i3);
            String strOptString = jSONObject6.optString("id");
            JSONArray jSONArray7 = new JSONArray();
            if (string.equals(jSONObject6.optString("purposeId"))) {
                if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                    strOptString = jSONObject6.optString("id");
                    jSONArrayN = n(strOptString);
                }
                if (jSONArrayN != null) {
                    for (int i4 = 0; i4 < jSONArrayN.length(); i4++) {
                        JSONObject jSONObject7 = jSONArrayN.getJSONObject(i4);
                        if (strOptString != null && strOptString.equals(jSONObject7.optString("customPreferenceId"))) {
                            jSONArray7.put(jSONObject7);
                            jSONObject6.put("customPreferenceOptions", jSONArray7);
                        }
                    }
                }
                jSONArray6.put(jSONObject6);
                jSONObject2.put("customPreferences", jSONArray6);
            } else {
                jSONArray6 = new JSONArray();
            }
        }
        jSONObject2.put("customPreferences", jSONArray6);
        jSONArray.put(jSONObject2);
        return jSONArrayN;
    }

    public final void e() {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        String string = dVar.b().getString("OT_UC_PURPOSES_PURPOSE_SERVER_DATA", "{}");
        String string2 = dVar.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", "{}");
        String string3 = dVar.b().getString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", "{}");
        try {
            this.d = new JSONObject(string);
            this.e = new JSONObject(string2);
            this.f = new JSONObject(string3);
        } catch (JSONException e) {
            Z.p("Error in initializing user state object :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final void f(int i, JSONArray jSONArray, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = jSONArray.getJSONObject(i);
        String strOptString = jSONObject2.optString("id");
        if (jSONObject2.has("customPreferences")) {
            JSONArray jSONArray2 = jSONObject2.getJSONArray("customPreferences");
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                JSONObject jSONObject3 = new JSONObject();
                JSONObject jSONObject4 = jSONArray2.getJSONObject(i2);
                this.b.getClass();
                retrofit2.adapter.rxjava3.d.k("id", jSONObject3, jSONObject4);
                retrofit2.adapter.rxjava3.d.k("name", jSONObject3, jSONObject4);
                retrofit2.adapter.rxjava3.d.k(OTUXParamsKeys.OT_UX_DESCRIPTION, jSONObject3, jSONObject4);
                retrofit2.adapter.rxjava3.d.k("selectionType", jSONObject3, jSONObject4);
                jSONObject3.put("selectionType", "MULTI_CHOICE");
                retrofit2.adapter.rxjava3.d.k("displayAs", jSONObject3, jSONObject4);
                retrofit2.adapter.rxjava3.d.k("required", jSONObject3, jSONObject4);
                jSONObject3.put("purposeId", strOptString);
                jSONObject.put(jSONObject4.optString("id"), jSONObject3);
            }
            OTLogger.c("UCPurposesDataHandler", 3, "customPrefObjectToSave :" + jSONObject);
            this.a.b().edit().putString("OT_UC_PURPOSES_CUSTOM_PREF_SERVER_DATA", String.valueOf(jSONObject)).apply();
        }
    }

    public final void g(String str, String str2, String str3, boolean z) {
        try {
            if (this.e.has(str2)) {
                JSONObject jSONObjectOptJSONObject = this.e.optJSONObject(str2);
                if (U.f(str, z, jSONObjectOptJSONObject, jSONObjectOptJSONObject.optString("customPreferenceId"))) {
                    OTLogger.c("UCPurposesDataHandler", 3, "Updated Custom Preference options: " + str3 + " of Custom Preference Id: " + str + " with status: " + z);
                    return;
                }
            }
            OTLogger.c("UCPurposesDataHandler", 5, "Invalid id passed to update custom preference options");
        } catch (JSONException e) {
            Z.p("Error in updating consent for CP options :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final void h(String str, String str2, boolean z) {
        JSONObject jSONObjectOptJSONObject;
        try {
            if (this.e.has(str2) && (jSONObjectOptJSONObject = this.e.optJSONObject(str2)) != null) {
                U.f(str, z, jSONObjectOptJSONObject, jSONObjectOptJSONObject.optString("customPreferenceId"));
            }
            OTLogger.c("UCPurposesDataHandler", 3, "Updated CustomPref options object : " + this.e.optJSONObject(str2));
            U.e(this.a, this.d, this.f, this.e);
            r(this.e);
            e();
        } catch (JSONException e) {
            Z.p("Error in updating consent for CP options :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final void j(String str, boolean z) {
        try {
            JSONObject jSONObjectOptJSONObject = this.d.optJSONObject(str);
            String str2 = "ACTIVE";
            if (!this.d.has(str)) {
                OTLogger.c("UCPurposesDataHandler", 5, "Invalid ID passed to update UCP Consent values");
                return;
            }
            if (!z) {
                str2 = "OPT_OUT";
            }
            jSONObjectOptJSONObject.put("userConsentStatus", str2);
            OTLogger.c("UCPurposesDataHandler", 3, "Updated purpose id: " + str + " with status: " + z);
            if (z) {
                return;
            }
            p(str, this.a.b().getString("OT_UCP_PURPOSE_RELATION_DATA", "{}"));
        } catch (JSONException e) {
            Z.p("Error in updating consent for purposes :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final void k(JSONObject jSONObject) {
        JSONArray jSONArrayNames;
        String str;
        String str2 = "customPreferences";
        JSONObject jSONObject2 = new JSONObject();
        if (jSONObject.has(OTVendorListMode.GENERAL)) {
            jSONObject2.put(OTVendorListMode.GENERAL, jSONObject.getJSONObject(OTVendorListMode.GENERAL));
        }
        String str3 = OTUXParamsKeys.OT_UX_DESCRIPTION;
        if (jSONObject.has(OTUXParamsKeys.OT_UX_DESCRIPTION)) {
            jSONObject2.put(OTUXParamsKeys.OT_UX_DESCRIPTION, jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_DESCRIPTION));
        }
        if (jSONObject.has("title")) {
            jSONObject2.put("title", jSONObject.getJSONObject("title"));
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BUTTONS)) {
            jSONObject2.put(OTUXParamsKeys.OT_UX_BUTTONS, jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_BUTTONS));
        }
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        dVar.b().edit().putString("OT_UC_PURPOSES_UI_SERVER_DATA", String.valueOf(jSONObject2)).apply();
        OTLogger.c("UCPurposesDataHandler", 3, "Saved server UCPurpose UI Data :" + dVar.b().getString("OT_UC_PURPOSES_UI_SERVER_DATA", ""));
        JSONObject jSONObject3 = new JSONObject();
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("purposes");
        JSONObject jSONObject4 = this.d;
        if (jSONArrayOptJSONArray != null) {
            int i = 0;
            while (i < jSONArrayOptJSONArray.length()) {
                JSONObject jSONObject5 = new JSONObject();
                JSONObject jSONObject6 = jSONArrayOptJSONArray.getJSONObject(i);
                this.b.getClass();
                retrofit2.adapter.rxjava3.d.k("id", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("version", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("label", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k(str3, jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("status", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("newVersionAvailable", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("purposeType", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("consentLifeSpan", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("externalReference", jSONObject5, jSONObject6);
                retrofit2.adapter.rxjava3.d.k("order", jSONObject5, jSONObject6);
                i(jSONObject6.optString("id"), jSONObject5, this.d);
                jSONObject5.put("defaultConsentStatus", "OPT_OUT");
                jSONObject4.put(jSONObject6.optString("id"), jSONObject5);
                i++;
                jSONArrayOptJSONArray = jSONArrayOptJSONArray;
                str3 = str3;
            }
            dVar.b().edit().putString("OT_UC_PURPOSES_PURPOSE_SERVER_DATA", String.valueOf(jSONObject4)).apply();
            OTLogger.c("UCPurposesDataHandler", 3, "Saved UC Purpose Server Data :" + dVar.b().getString("OT_UC_PURPOSES_PURPOSE_SERVER_DATA", ""));
        }
        JSONArray jSONArrayOptJSONArray2 = jSONObject.optJSONArray("purposes");
        JSONObject jSONObject7 = new JSONObject();
        int i2 = 6;
        if (jSONArrayOptJSONArray2 != null) {
            int i3 = 0;
            while (i3 < jSONArrayOptJSONArray2.length()) {
                try {
                    o(i3, jSONArrayOptJSONArray2, jSONObject7);
                } catch (JSONException e) {
                    Z.p("Error in saving topics data :", e, "UCPurposesDataHandler", i2);
                }
                OTLogger.c("UCPurposesDataHandler", 3, "Saved server Topic Data :" + dVar.b().getString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", ""));
                i3++;
                i2 = 6;
            }
        }
        try {
            JSONArray jSONArrayOptJSONArray3 = jSONObject.optJSONArray("purposes");
            JSONObject jSONObject8 = new JSONObject();
            if (jSONArrayOptJSONArray3 != null) {
                for (int i4 = 0; i4 < jSONArrayOptJSONArray3.length(); i4++) {
                    f(i4, jSONArrayOptJSONArray3, jSONObject8);
                }
                OTLogger.c("UCPurposesDataHandler", 3, "Saved server Custom Pref Data :" + dVar.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_SERVER_DATA", ""));
            }
        } catch (JSONException e2) {
            Z.p("Error in saving custom pref data :", e2, "UCPurposesDataHandler", 6);
        }
        JSONArray jSONArrayOptJSONArray4 = jSONObject.optJSONArray("purposes");
        JSONObject jSONObject9 = this.e;
        if (jSONArrayOptJSONArray4 != null) {
            int i5 = 0;
            while (i5 < jSONArrayOptJSONArray4.length()) {
                try {
                    JSONObject jSONObject10 = jSONArrayOptJSONArray4.getJSONObject(i5);
                    String strOptString = jSONObject10.optString("id");
                    if (jSONObject10.has(str2)) {
                        JSONArray jSONArray = jSONObject10.getJSONArray(str2);
                        str = str2;
                        for (int i6 = 0; i6 < jSONArray.length(); i6++) {
                            try {
                                l(jSONObject9, jSONArray, i6, strOptString);
                            } catch (JSONException e3) {
                                e = e3;
                                Z.p("Error in saving CP options data :", e, "UCPurposesDataHandler", 6);
                                OTLogger.c("UCPurposesDataHandler", 3, "Saved server Custom Pref options Data :" + dVar.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", ""));
                                i5++;
                                str2 = str;
                            }
                        }
                    } else {
                        str = str2;
                    }
                } catch (JSONException e4) {
                    e = e4;
                    str = str2;
                }
                OTLogger.c("UCPurposesDataHandler", 3, "Saved server Custom Pref options Data :" + dVar.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", ""));
                i5++;
                str2 = str;
            }
        }
        e();
        JSONArray jSONArrayOptJSONArray5 = jSONObject.optJSONArray("purposes");
        if (jSONArrayOptJSONArray5 != null) {
            for (int i7 = 0; i7 < jSONArrayOptJSONArray5.length(); i7++) {
                try {
                    m(jSONArrayOptJSONArray5.getJSONObject(i7), jSONObject3);
                } catch (JSONException e5) {
                    Z.o("UCP: error while creating broadcasting object:", e5, "UCPurposesDataHandler");
                }
            }
        }
        L.i(jSONObject3, dVar.b().edit(), "OT_UCP_PURPOSE_RELATION_DATA");
        Context context = this.c;
        if (retrofit2.adapter.rxjava3.d.o(jSONObject3) || (jSONArrayNames = jSONObject3.names()) == null) {
            return;
        }
        for (int i8 = 0; i8 < jSONArrayNames.length(); i8++) {
            try {
                String string = jSONArrayNames.getString(i8);
                JSONObject jSONObject11 = jSONObject3.getJSONObject(string);
                OTLogger.c("OTConsentChanges", 4, "UCP: Sending " + string + " broadcast, value = " + jSONObject11);
                Intent intent = new Intent(string);
                intent.putExtra(OTBroadcastServiceKeys.UCP_EVENT_STATUS, jSONObject11.toString());
                intent.setPackage(context.getApplicationContext().getPackageName());
                context.sendBroadcast(intent);
            } catch (JSONException e6) {
                Z.o("UCP: Failed to broadcast UCP consent changes,", e6, "OTConsentChanges");
                return;
            }
        }
    }

    public final void l(JSONObject jSONObject, JSONArray jSONArray, int i, String str) throws JSONException {
        JSONObject jSONObject2 = jSONArray.getJSONObject(i);
        String strOptString = jSONObject2.optString("id");
        if (jSONObject2.has("customPreferenceOptions")) {
            JSONArray jSONArray2 = jSONObject2.getJSONArray("customPreferenceOptions");
            OTLogger.c("UCPurposesDataHandler", 3, "customPrefArraylength() optionsArray :" + jSONArray2.length());
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                JSONObject jSONObject3 = new JSONObject();
                JSONObject jSONObject4 = jSONArray2.getJSONObject(i2);
                String str2 = jSONObject4.optString("id") + str + strOptString;
                this.b.getClass();
                retrofit2.adapter.rxjava3.d.k("id", jSONObject3, jSONObject4);
                retrofit2.adapter.rxjava3.d.k("label", jSONObject3, jSONObject4);
                jSONObject3.put("customPreferenceId", strOptString);
                jSONObject3.put("purposeOptionsId", str2);
                jSONObject3.put("purposeId", str);
                i(str2, jSONObject3, this.e);
                jSONObject.put(str2, jSONObject3);
            }
            this.a.b().edit().putString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", String.valueOf(jSONObject)).apply();
        }
    }

    public final void m(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        JSONObject jSONObject3 = new JSONObject();
        JSONObject jSONObject4 = new JSONObject();
        String strOptString = jSONObject.optString("id");
        jSONObject3.put("status", u(strOptString));
        if (jSONObject.has("topics")) {
            JSONArray jSONArray = jSONObject.getJSONObject("topics").getJSONArray("options");
            for (int i = 0; i < jSONArray.length(); i++) {
                String strOptString2 = jSONArray.getJSONObject(i).optString("id", "");
                int iA = a(strOptString2, strOptString);
                if (iA == -1) {
                    iA = 0;
                }
                jSONObject4.put(strOptString2, iA);
            }
        }
        jSONObject3.put("topics", jSONObject4);
        JSONObject jSONObject5 = new JSONObject();
        if (jSONObject.has("customPreferences")) {
            JSONArray jSONArray2 = jSONObject.getJSONArray("customPreferences");
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                JSONObject jSONObject6 = jSONArray2.getJSONObject(i2);
                String string = jSONObject6.getString("id");
                JSONArray jSONArray3 = jSONObject6.getJSONArray("customPreferenceOptions");
                JSONObject jSONObject7 = new JSONObject();
                for (int i3 = 0; i3 < jSONArray3.length(); i3++) {
                    String string2 = jSONArray3.getJSONObject(i3).getString("id");
                    int iB = b(string2, strOptString, string);
                    if (iB == -1) {
                        iB = 0;
                    }
                    jSONObject7.put(string2, iB);
                }
                jSONObject5.put(string, jSONObject7);
            }
        }
        jSONObject3.put("custom_preferences", jSONObject5);
        jSONObject2.put(strOptString, jSONObject3);
    }

    public final JSONArray n(String str) {
        String string = this.a.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", "");
        JSONArray jSONArray = new JSONArray();
        try {
            JSONObject jSONObject = new JSONObject(string);
            for (int i = 0; i < jSONObject.length(); i++) {
                JSONObject jSONObject2 = jSONObject.getJSONObject(jSONObject.names().get(i).toString());
                if (str.equals(jSONObject2.optString("customPreferenceId"))) {
                    jSONArray.put(jSONObject2);
                }
            }
        } catch (JSONException e) {
            Z.p("Error in fetching CP options data by purposeCPId  :", e, "UCPurposesDataHandler", 6);
        }
        OTLogger.c("UCPurposesDataHandler", 3, "Options by Purpose and CustomPrefId :" + jSONArray);
        return jSONArray;
    }

    public final void o(int i, JSONArray jSONArray, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = jSONArray.getJSONObject(i);
        String strOptString = jSONObject2.optString("id");
        if (jSONObject2.has("topics")) {
            JSONObject jSONObject3 = jSONObject2.getJSONObject("topics");
            if (jSONObject3.has("options")) {
                JSONArray jSONArray2 = jSONObject3.getJSONArray("options");
                for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                    JSONObject jSONObject4 = new JSONObject();
                    JSONObject jSONObject5 = jSONArray2.getJSONObject(i2);
                    this.b.getClass();
                    retrofit2.adapter.rxjava3.d.k("id", jSONObject4, jSONObject5);
                    retrofit2.adapter.rxjava3.d.k("name", jSONObject4, jSONObject5);
                    retrofit2.adapter.rxjava3.d.k("integrationKey", jSONObject4, jSONObject5);
                    jSONObject4.put("purposeId", strOptString);
                    jSONObject4.put("purposeTopicId", jSONObject5.optString("id") + strOptString);
                    i(jSONObject5.optString("id") + strOptString, jSONObject4, this.f);
                    jSONObject.put(jSONObject5.optString("id") + strOptString, jSONObject4);
                }
                this.a.b().edit().putString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", String.valueOf(jSONObject)).apply();
            }
        }
    }

    public final void p(String str, String str2) throws JSONException {
        JSONObject jSONObject = new JSONObject(str2);
        if (jSONObject.has(str)) {
            JSONObject jSONObject2 = jSONObject.getJSONObject(str);
            if (jSONObject2.has("topics") && !retrofit2.adapter.rxjava3.d.o(jSONObject2.getJSONObject("topics"))) {
                JSONArray jSONArrayNames = jSONObject2.getJSONObject("topics").names();
                for (int i = 0; i < jSONArrayNames.length(); i++) {
                    String string = jSONArrayNames.getString(i);
                    t(string.trim() + str.trim(), string, false);
                }
            }
            JSONObject jSONObject3 = jSONObject2.getJSONObject("custom_preferences");
            if (retrofit2.adapter.rxjava3.d.o(jSONObject3)) {
                return;
            }
            for (int i2 = 0; i2 < jSONObject3.length(); i2++) {
                String string2 = jSONObject3.names().getString(i2);
                JSONObject jSONObject4 = jSONObject3.getJSONObject(string2);
                for (int i3 = 0; i3 < jSONObject4.length(); i3++) {
                    String string3 = jSONObject4.names().getString(i3);
                    g(string2, string3.trim() + str.trim() + string2.trim(), string3, false);
                }
            }
        }
    }

    public final void q(String str, String str2, boolean z) {
        try {
            if (this.f.has(str)) {
                JSONObject jSONObjectOptJSONObject = this.f.optJSONObject(str);
                U.f(str2, z, jSONObjectOptJSONObject, jSONObjectOptJSONObject.optString("id"));
            }
            OTLogger.c("UCPurposesDataHandler", 3, "Updated topic object : " + this.f.optJSONObject(str));
            U.e(this.a, this.d, this.f, this.e);
            r(this.f);
        } catch (JSONException e) {
            Z.p("Error in updating consent for topics :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final void r(JSONObject jSONObject) {
        SharedPreferences.Editor editorEdit;
        String strValueOf;
        String str;
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject(itKeys.next());
            if (jSONObjectOptJSONObject != null) {
                try {
                    jSONObjectOptJSONObject.put("transactionType", jSONObjectOptJSONObject.optString("userConsentStatus"));
                } catch (JSONException e) {
                    Z.p("Error while updating previous selection to latest selection :", e, "UCPurposesDataHandler", 6);
                }
            }
        }
        boolean zEquals = jSONObject.equals(this.d);
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        if (zEquals) {
            editorEdit = dVar.b().edit();
            strValueOf = String.valueOf(this.d);
            str = "OT_UC_PURPOSES_PURPOSE_SERVER_DATA";
        } else if (jSONObject.equals(this.f)) {
            editorEdit = dVar.b().edit();
            strValueOf = String.valueOf(this.f);
            str = "OT_UC_PURPOSES_TOPIC_SERVER_DATA";
        } else {
            if (!jSONObject.equals(this.e)) {
                return;
            }
            editorEdit = dVar.b().edit();
            strValueOf = String.valueOf(this.e);
            str = "OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA";
        }
        editorEdit.putString(str, strValueOf).apply();
    }

    public final JSONArray s(String str) {
        String string = this.a.b().getString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", "");
        JSONArray jSONArray = new JSONArray();
        try {
            JSONObject jSONObject = new JSONObject(string);
            for (int i = 0; i < jSONObject.length(); i++) {
                JSONObject jSONObject2 = jSONObject.getJSONObject(jSONObject.names().get(i).toString());
                if (str.equals(jSONObject2.optString("purposeId"))) {
                    jSONArray.put(jSONObject2);
                }
            }
        } catch (JSONException e) {
            Z.p("Error in fetching topics data by purpose :", e, "UCPurposesDataHandler", 6);
        }
        OTLogger.c("UCPurposesDataHandler", 3, "Topics by PurposeId :" + jSONArray);
        return jSONArray;
    }

    public final void t(String str, String str2, boolean z) {
        try {
            if (!this.f.has(str)) {
                OTLogger.c("UCPurposesDataHandler", 5, "Invalid id passed to update topics");
                return;
            }
            JSONObject jSONObjectOptJSONObject = this.f.optJSONObject(str);
            U.f(str2, z, jSONObjectOptJSONObject, jSONObjectOptJSONObject.optString("id"));
            OTLogger.c("UCPurposesDataHandler", 3, "Updated topic id: " + str2 + " with status: " + z);
        } catch (JSONException e) {
            Z.p("Error in updating consent for topics :", e, "UCPurposesDataHandler", 6);
        }
    }

    public final int u(String str) {
        int iD = U.d(str, this.d);
        OTLogger.c("UCPurposesDataHandler", 4, "UCP: Consent Status for Purpose id " + str + " : " + iD);
        return iD;
    }
}
