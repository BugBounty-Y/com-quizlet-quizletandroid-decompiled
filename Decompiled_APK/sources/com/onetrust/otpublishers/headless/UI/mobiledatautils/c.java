package com.onetrust.otpublishers.headless.UI.mobiledatautils;

import android.content.Context;
import android.os.Bundle;
import androidx.navigation.internal.m;
import androidx.room.s;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.data.repository.user.e;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.adapter.rxjava3.d;

/* loaded from: classes2.dex */
public final class c {
    public JSONObject a;
    public String b;
    public boolean c;
    public String d;
    public boolean e;
    public boolean f;
    public boolean g;
    public String h;
    public boolean i;
    public String j;
    public String k;
    public Zh l;
    public s m;
    public OTPublishersHeadlessSDK n;
    public Context o;

    public static void b(e eVar, String str, JSONObject jSONObject) {
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) eVar.b).b)) {
            m mVar = (m) eVar.b;
            String strOptString = jSONObject.optString("PcLinksTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.b)) {
                strOptString = (String) mVar.b;
            }
            mVar.b = strOptString;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) eVar.b).g)) {
            ((m) eVar.b).g = str;
        }
    }

    public static boolean c(JSONObject jSONObject) throws JSONException {
        boolean z;
        boolean zL = d.l(jSONObject.optJSONArray("GeneralVendorsIds"));
        if (!jSONObject.has("SubGroups") && !zL) {
            return true;
        }
        if (!jSONObject.has("SubGroups") || jSONObject.getBoolean("IsIabPurpose")) {
            z = false;
        } else {
            JSONArray jSONArray = jSONObject.getJSONArray("SubGroups");
            z = false;
            for (int i = 0; i < jSONArray.length(); i++) {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                if (jSONObject2.getBoolean("IsIabPurpose")) {
                    return false;
                }
                if (!d.l(jSONObject2.optJSONArray("GeneralVendorsIds"))) {
                    z = true;
                }
            }
        }
        return !zL || z;
    }

    public static boolean e(JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("ShowSDKListLink") && !jSONObject.getBoolean("ShowSDKListLink")) {
            return false;
        }
        if (!jSONObject.getBoolean("IsIabPurpose") && jSONObject.getJSONArray("FirstPartyCookies").length() > 0) {
            return true;
        }
        if (jSONObject.has("SubGroups")) {
            JSONArray jSONArray = jSONObject.getJSONArray("SubGroups");
            for (int i = 0; i < jSONArray.length(); i++) {
                if (!jSONArray.getJSONObject(i).getBoolean("IsIabPurpose")) {
                    return true;
                }
            }
        }
        return false;
    }

    public final Bundle a(HashMap map) throws JSONException {
        Bundle bundle = new Bundle();
        try {
            if (!this.a.getBoolean("IsIabPurpose") && !d.l(this.a.getJSONArray("GeneralVendorsIds"))) {
                map.put(this.d, this.b);
            }
            if (this.a.has("SubGroups")) {
                JSONArray jSONArray = this.a.getJSONArray("SubGroups");
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject = jSONArray.getJSONObject(i);
                    if (!jSONObject.getBoolean("IsIabPurpose")) {
                        map.put(jSONObject.getString("CustomGroupId"), jSONObject.getString("Type"));
                    }
                }
            }
            bundle.putBoolean("IS_FILTERED_VENDOR_LIST", true);
            bundle.putString("PURPOSE_MAP", map.toString());
            return bundle;
        } catch (JSONException e) {
            Z.p("General vendor: error while setting filtered groups ", e, "PC Detail", 6);
            return bundle;
        }
    }

    public final Bundle d(HashMap map) throws JSONException {
        Bundle bundle = new Bundle();
        try {
            if (!this.c && this.a.getBoolean("IsIabPurpose")) {
                map.put(this.d, this.b);
            }
            if (this.a.has("SubGroups")) {
                JSONArray jSONArray = this.a.getJSONArray("SubGroups");
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject = jSONArray.getJSONObject(i);
                    if (jSONObject.getBoolean("IsIabPurpose")) {
                        map.put(jSONObject.getString("CustomGroupId"), jSONObject.getString("Type"));
                    }
                }
            }
            bundle.putBoolean("IS_FILTERED_VENDOR_LIST", true);
            bundle.putString("PURPOSE_MAP", map.toString());
            return bundle;
        } catch (JSONException e) {
            Z.p("error in parsing vendorlist link on setCategoriesForVendorList: ", e, "PC Detail", 6);
            return bundle;
        }
    }
}
