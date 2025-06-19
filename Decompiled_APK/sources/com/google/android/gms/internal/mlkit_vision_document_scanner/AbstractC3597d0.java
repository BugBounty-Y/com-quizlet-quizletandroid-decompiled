package com.google.android.gms.internal.mlkit_vision_document_scanner;

import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3597d0 {
    public static final /* synthetic */ int a = 0;

    public static String a(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar) {
        JSONObject jSONObject;
        String string;
        String string2;
        JSONObject jSONObject2 = new JSONObject();
        try {
            string2 = dVar.b().getString("OT_API_FETCH_STATUS_DATA", "");
        } catch (JSONException e) {
            com.google.android.gms.measurement.internal.Z.p("error while getting status data json, err: ", e, "OneTrust", 6);
        }
        JSONObject jSONObject3 = !com.onetrust.otpublishers.headless.Internal.a.j(string2) ? new JSONObject(string2) : new JSONObject();
        String string3 = dVar.b().getString("OTT_DOMAIN_DATA", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
            jSONObject = new JSONObject();
        } else {
            try {
                jSONObject = new JSONObject(string3);
            } catch (JSONException e2) {
                com.google.android.gms.measurement.internal.Z.p("error while returning domain data, err: ", e2, "OneTrust", 6);
            }
        }
        try {
            string = dVar.b().getString("OT_CULTURE_DATA", "");
        } catch (JSONException e3) {
            com.google.android.gms.measurement.internal.Z.p("Error while getting culture data json on getCultureData, err: ", e3, "OneTrust", 6);
        }
        JSONObject jSONObject4 = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : new JSONObject();
        try {
            jSONObject2.put("status", jSONObject3);
        } catch (JSONException e4) {
            com.google.android.gms.measurement.internal.Z.p("Exception thrown while constructing ott data, err : ", e4, "OTSharedPreferenceHelper", 3);
        }
        try {
            jSONObject2.put("domain", jSONObject);
        } catch (JSONException e5) {
            com.google.android.gms.measurement.internal.Z.p("Exception thrown while constructing ott data, err : ", e5, "OTSharedPreferenceHelper", 3);
        }
        try {
            jSONObject2.put("culture", jSONObject4);
        } catch (JSONException e6) {
            com.google.android.gms.measurement.internal.Z.p("Exception thrown while constructing ott data, err : ", e6, "OTSharedPreferenceHelper", 3);
        }
        return jSONObject2.toString();
    }
}
