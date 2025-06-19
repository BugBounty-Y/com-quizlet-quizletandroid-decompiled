package org.prebid.mobile.rendering.bidding.data.bid;

import android.text.TextUtils;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class Prebid {
    public final HashMap a = new HashMap();
    public final HashMap b = new HashMap();
    public String c;
    public String d;

    public static JSONObject a(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        try {
            jSONObject2.put("id", str);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        Utils.a(jSONObject, "storedrequest", jSONObject2);
        int i = PrebidMobile.a;
        if (!TextUtils.isEmpty("")) {
            JSONObject jSONObject3 = new JSONObject();
            Utils.a(jSONObject3, "id", "");
            Utils.a(jSONObject, "storedauctionresponse", jSONObject3);
        }
        LinkedHashMap linkedHashMap = PrebidMobile.d;
        if (!linkedHashMap.isEmpty()) {
            JSONArray jSONArray = new JSONArray();
            for (Map.Entry entry : linkedHashMap.entrySet()) {
                String str2 = (String) entry.getKey();
                String str3 = (String) entry.getValue();
                if (!TextUtils.isEmpty(str2) && !TextUtils.isEmpty(str3)) {
                    JSONObject jSONObject4 = new JSONObject();
                    Utils.a(jSONObject4, "bidder", str2);
                    Utils.a(jSONObject4, "id", str3);
                }
            }
            Utils.a(jSONObject, "storedbidresponse", jSONArray);
        }
        return jSONObject;
    }
}
