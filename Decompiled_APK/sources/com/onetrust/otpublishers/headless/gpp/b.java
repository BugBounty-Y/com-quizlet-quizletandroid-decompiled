package com.onetrust.otpublishers.headless.gpp;

import android.content.Context;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import java.util.HashMap;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public final Context a;
    public final HashMap b = new HashMap();
    public final com.onetrust.otpublishers.headless.Internal.Preferences.a c;

    public b(@NonNull Context context) {
        this.c = new com.onetrust.otpublishers.headless.Internal.Preferences.a(context);
        this.a = context;
        c();
    }

    public final void a() {
        HashMap map = this.b;
        if (map.isEmpty()) {
            c();
        }
        if (map.keySet().isEmpty()) {
            return;
        }
        for (String str : map.keySet()) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && str.startsWith("IABGPP_TCFEU2_")) {
                this.c.b(str);
            }
        }
    }

    public final void b(String str, String str2, String str3) {
        OTLogger.c("GppDataStorage", 3, "Saving Gpp data to default Shared Preferences");
        OTLogger.c("OneTrust", 3, "Gpp string: " + str);
        com.onetrust.otpublishers.headless.Internal.Preferences.a aVar = this.c;
        aVar.c(OTGppKeys.IAB_GPP_HDR_GPP_STRING, str);
        OTLogger.c("GppDataStorage", 3, "Gpp version: 1");
        aVar.a(1, OTGppKeys.IAB_GPP_HDR_VERSION);
        OTLogger.c("GppDataStorage", 3, "Gpp Section Ids: " + str2);
        aVar.c(OTGppKeys.IAB_GPP_HDR_SECTIONS, str2);
        OTLogger.c("GppDataStorage", 3, "Gpp current region section id: " + str3);
        aVar.c(OTGppKeys.IAB_GPP_GPP_SID, str3);
    }

    public final void c() {
        HashMap map = this.b;
        map.put(OTGppKeys.IAB_GPP_HDR_GPP_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_HDR_VERSION, 10);
        map.put(OTGppKeys.IAB_GPP_HDR_SECTIONS, 30);
        map.put(OTGppKeys.IAB_GPP_GPP_SID, 30);
        map.put(OTGppKeys.IAB_GPP_TCFEU2_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_USP1_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_US_NAT_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_CALIFORNIA_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_USVA_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_USCO_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_USCT_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_USUT_STRING, 30);
        map.put(OTGppKeys.IAB_GPP_CMPSDKID, 10);
        map.put(OTGppKeys.IAB_GPP_CMPSDKVERSION, 10);
        map.put(OTGppKeys.IAB_GPP_POLICYVERSION, 10);
        map.put(OTGppKeys.IAB_GPP_GDPRAPPLIES, 10);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERCC, 30);
        map.put(OTGppKeys.IAB_GPP_PURPOSEONETREATMENT, 10);
        map.put(new com.onetrust.otpublishers.headless.Internal.Preferences.e(this.a).l() ? OTGppKeys.IAB_GPP_USENONSTANDARDTEXTS : OTGppKeys.IAB_GPP_USENONSTANDARDSTACKS, 10);
        map.put(OTGppKeys.IAB_GPP_VENDORCONSENTS, 30);
        map.put(OTGppKeys.IAB_GPP_VENDORLEGITIMATEINTERESTS, 30);
        map.put(OTGppKeys.IAB_GPP_PURPOSECONSENTS, 30);
        map.put(OTGppKeys.IAB_GPP_PURPOSELEGITIMATEINTERESTS, 30);
        map.put(OTGppKeys.IAB_GPP_SPECIALFEATURESOPTINS, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERRESTRICTIONS, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERCONSENT, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERLEGITIMATEINTERESTS, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERCUSTOMPURPOSESCONSENTS, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_1, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_2, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_3, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_4, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_5, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_6, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_7, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_8, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_9, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_10, 30);
        map.put(OTGppKeys.IAB_GPP_PUBLISHER_RESTRICTION_11, 30);
        map.put(OTGppKeys.IAB_GPP_USP1_VERSION, 10);
        map.put(OTGppKeys.IAB_GPP_USP1_NOTICE, 30);
        map.put(OTGppKeys.IAB_GPP_USP1_OPT_OUT, 30);
        map.put(OTGppKeys.IAB_GPP_USP1_LSPA_COVERED, 30);
    }

    public final void d(JSONObject jSONObject) throws JSONException {
        HashMap map = this.b;
        for (String str : map.keySet()) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                Integer num = (Integer) map.get(str);
                Integer num2 = 10;
                boolean zEquals = num2.equals(num);
                com.onetrust.otpublishers.headless.Internal.Preferences.a aVar = this.c;
                if (zEquals && aVar.a.contains(str)) {
                    jSONObject.put(str, aVar.d(str));
                }
                Integer num3 = 30;
                if (num3.equals(num) && aVar.a.contains(str)) {
                    jSONObject.put(str, aVar.e(str));
                }
            }
        }
    }

    public final void e(JSONObject jSONObject) throws JSONException {
        HashMap map = this.b;
        for (String str : map.keySet()) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                Integer num = (Integer) map.get(str);
                Integer num2 = 10;
                boolean zEquals = num2.equals(num);
                com.onetrust.otpublishers.headless.Internal.Preferences.a aVar = this.c;
                if (zEquals && aVar.a.contains(str)) {
                    jSONObject.put(str, aVar.d(str));
                }
                Integer num3 = 30;
                if (num3.equals(num) && aVar.a.contains(str)) {
                    jSONObject.put(str, aVar.e(str));
                }
                aVar.b(str);
            }
        }
    }

    public final void f(JSONObject jSONObject) {
        HashMap map = this.b;
        for (String str : map.keySet()) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                Integer num = (Integer) map.get(str);
                boolean zHas = jSONObject.has(str);
                com.onetrust.otpublishers.headless.Internal.Preferences.a aVar = this.c;
                if (zHas) {
                    Integer num2 = 10;
                    if (num2.equals(num)) {
                        aVar.a(jSONObject.optInt(str), str);
                    }
                }
                if (jSONObject.has(str)) {
                    Integer num3 = 30;
                    if (num3.equals(num)) {
                        aVar.c(str, jSONObject.optString(str));
                    }
                }
            }
        }
    }
}
