package com.onetrust.otpublishers.headless.UI.TVUI.datautils;

import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class e {
    public static e E;
    public String D;
    public JSONObject a;
    public JSONObject b;
    public String c = "";
    public String d = "";
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
    public String o = "";
    public String p = "";
    public String q = "";
    public String r = "";
    public String s = "";
    public String t = "";
    public String u = "";
    public String v = "";
    public String w = "";
    public String x = "";
    public String y = "";
    public String z = "";
    public String A = "";
    public String B = "";
    public String C = OTVendorListMode.IAB;

    public static synchronized e a() {
        try {
            if (E == null) {
                E = new e();
            }
        } catch (Throwable th) {
            throw th;
        }
        return E;
    }

    public static String b(JSONObject jSONObject, JSONObject jSONObject2, boolean z) throws JSONException {
        String strOptString;
        String strOptString2 = jSONObject.optString("SDKLanguageCode");
        if (!jSONObject2.has("urls")) {
            return "";
        }
        try {
            JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray("urls");
            String str = null;
            if (jSONArrayOptJSONArray != null) {
                int i = 0;
                while (true) {
                    if (i >= jSONArrayOptJSONArray.length()) {
                        break;
                    }
                    JSONObject jSONObject3 = jSONArrayOptJSONArray.getJSONObject(i);
                    if (strOptString2.equalsIgnoreCase(jSONObject3.optString("langId"))) {
                        strOptString = jSONObject3.optString(z ? "legIntClaim" : "privacy");
                    } else {
                        strOptString = null;
                    }
                    if (strOptString != null) {
                        str = strOptString;
                        break;
                    }
                    i++;
                }
            }
            return str != null ? str : "";
        } catch (JSONException e) {
            Z.p("Error on getting iab2v2 vendor policy url, error = ", e, "IAB2V2Flow", 6);
            return "";
        }
    }

    public final void c(JSONObject jSONObject, String str) {
        String strOptString;
        this.b = jSONObject;
        this.C = str;
        if (this.a == null || jSONObject == null) {
            return;
        }
        this.c = jSONObject.optString("name");
        this.h = this.a.optString("PCenterVendorListLifespan") + " : ";
        this.j = this.a.optString("PCenterVendorListDisclosure");
        this.k = this.a.optString("BConsentPurposesText");
        this.l = this.a.optString("BLegitimateInterestPurposesText");
        this.o = this.a.optString("BSpecialFeaturesText");
        this.n = this.a.optString("BSpecialPurposesText");
        this.m = this.a.optString("BFeaturesText");
        this.D = this.a.optString("IabType");
        if (OTVendorListMode.IAB.equalsIgnoreCase(this.C)) {
            String str2 = this.D;
            JSONObject jSONObject2 = this.a;
            JSONObject jSONObject3 = this.b;
            strOptString = com.onetrust.otpublishers.headless.Internal.a.l(str2) ? b(jSONObject2, jSONObject3, false) : jSONObject3.optString("policyUrl");
        } else {
            strOptString = this.b.optString("policyUrl");
        }
        this.d = strOptString;
        this.e = com.onetrust.otpublishers.headless.Internal.a.l(this.D) ? b(this.a, this.b, true) : "";
        this.f = this.a.optString("PCenterViewPrivacyPolicyText");
        this.g = this.a.optString("PCIABVendorLegIntClaimText");
        this.i = assistantMode.utils.studiableMetadata.b.k(this.b.optLong("cookieMaxAgeSeconds"), this.a);
        this.p = this.a.optString("PCenterVendorListNonCookieUsage");
        this.y = this.a.optString("PCVListDataDeclarationText");
        this.z = this.a.optString("PCVListDataRetentionText");
        this.A = this.a.optString("PCVListStdRetentionText");
        this.B = this.a.optString("PCenterVendorListLifespanDays");
        this.q = this.b.optString("deviceStorageDisclosureUrl");
        this.r = this.a.optString("PCenterVendorListStorageIdentifier") + " : ";
        this.s = this.a.optString("PCenterVendorListStorageType") + " : ";
        this.t = this.a.optString("PCenterVendorListLifespan") + " : ";
        this.u = this.a.optString("PCenterVendorListStorageDomain") + " : ";
        this.v = this.a.optString("PCenterVendorListStoragePurposes") + " : ";
        this.w = this.a.optString("PCVLSDomainsUsed");
        this.x = this.a.optString("PCVLSUse") + " : ";
    }
}
