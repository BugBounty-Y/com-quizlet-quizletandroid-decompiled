package com.appsflyer.internal;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFh1cSDK {
    public AFi1xSDK AFAdRevenueData;
    public final AFh1bSDK getCurrencyIso4217Code;
    public final AFh1dSDK getRevenue;

    public AFh1cSDK(@NotNull JSONObject jSONObject) {
        Intrinsics.checkNotNullParameter(jSONObject, "");
        this.AFAdRevenueData = getCurrencyIso4217Code(jSONObject);
        this.getRevenue = getRevenue(jSONObject);
        this.getCurrencyIso4217Code = getMonetizationNetwork(jSONObject);
    }

    private static JSONObject AFAdRevenueData(JSONObject jSONObject, String str) throws JSONException, NullPointerException {
        JSONObject jSONObjectOptJSONObject;
        if (!jSONObject.has(str) || (jSONObjectOptJSONObject = jSONObject.getJSONArray(str).optJSONObject(0).optJSONObject("data")) == null) {
            return null;
        }
        return jSONObjectOptJSONObject.optJSONObject("v1");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r2v9, types: [kotlin.collections.K] */
    private static AFi1xSDK getCurrencyIso4217Code(JSONObject jSONObject) {
        Object objB;
        ?? arrayList;
        try {
            p pVar = r.b;
            JSONObject jSONObjectAFAdRevenueData = AFAdRevenueData(jSONObject, "r_debugger");
            if (jSONObjectAFAdRevenueData != null) {
                long j = jSONObjectAFAdRevenueData.getLong("ttl");
                int i = jSONObjectAFAdRevenueData.getInt("counter");
                String strOptString = jSONObjectAFAdRevenueData.optString("app_ver", "");
                String strOptString2 = jSONObjectAFAdRevenueData.optString("sdk_ver", "");
                float fOptDouble = (float) jSONObjectAFAdRevenueData.optDouble("ratio", 1.0d);
                JSONArray jSONArrayOptJSONArray = jSONObjectAFAdRevenueData.optJSONArray("tags");
                if (jSONArrayOptJSONArray != null) {
                    Intrinsics.checkNotNullExpressionValue(jSONArrayOptJSONArray, "");
                    arrayList = new ArrayList();
                    int length = jSONArrayOptJSONArray.length();
                    for (int i2 = 0; i2 < length; i2++) {
                        String string = jSONArrayOptJSONArray.getString(i2);
                        Intrinsics.checkNotNullExpressionValue(string, "");
                        arrayList.add(string);
                    }
                } else {
                    arrayList = K.a;
                }
                List list = arrayList;
                Intrinsics.checkNotNullExpressionValue(strOptString, "");
                Intrinsics.checkNotNullExpressionValue(strOptString2, "");
                objB = new AFi1xSDK(j, fOptDouble, list, i, strOptString, strOptString2);
            } else {
                objB = null;
            }
        } catch (Throwable th) {
            p pVar2 = r.b;
            objB = Z.b(th);
        }
        p pVar3 = r.b;
        return (AFi1xSDK) (objB instanceof q ? null : objB);
    }

    private static AFh1bSDK getMonetizationNetwork(JSONObject jSONObject) {
        Object objB;
        try {
            p pVar = r.b;
            JSONObject jSONObjectAFAdRevenueData = AFAdRevenueData(jSONObject, "meta_data");
            objB = jSONObjectAFAdRevenueData != null ? new AFh1bSDK(jSONObjectAFAdRevenueData.optDouble("send_rate", 1.0d)) : null;
        } catch (Throwable th) {
            p pVar2 = r.b;
            objB = Z.b(th);
        }
        return (AFh1bSDK) (objB instanceof q ? null : objB);
    }

    private static AFh1dSDK getRevenue(JSONObject jSONObject) {
        Object objB;
        try {
            p pVar = r.b;
            JSONObject jSONObjectAFAdRevenueData = AFAdRevenueData(jSONObject, "exc_mngr");
            objB = jSONObjectAFAdRevenueData != null ? new AFh1dSDK(jSONObjectAFAdRevenueData.getString("sdk_ver"), jSONObjectAFAdRevenueData.optInt("min", -1), jSONObjectAFAdRevenueData.optInt("expire", -1), jSONObjectAFAdRevenueData.optLong("ttl", -1L)) : null;
        } catch (Throwable th) {
            p pVar2 = r.b;
            objB = Z.b(th);
        }
        return (AFh1dSDK) (objB instanceof q ? null : objB);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!AFh1cSDK.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "");
        AFh1cSDK aFh1cSDK = (AFh1cSDK) obj;
        return Intrinsics.b(this.getRevenue, aFh1cSDK.getRevenue) && Intrinsics.b(this.getCurrencyIso4217Code, aFh1cSDK.getCurrencyIso4217Code) && Intrinsics.b(this.AFAdRevenueData, aFh1cSDK.AFAdRevenueData);
    }

    public final int hashCode() {
        AFh1dSDK aFh1dSDK = this.getRevenue;
        int iHashCode = (aFh1dSDK != null ? aFh1dSDK.hashCode() : 0) * 31;
        AFh1bSDK aFh1bSDK = this.getCurrencyIso4217Code;
        int iHashCode2 = (iHashCode + (aFh1bSDK != null ? aFh1bSDK.hashCode() : 0)) * 31;
        AFi1xSDK aFi1xSDK = this.AFAdRevenueData;
        return iHashCode2 + (aFi1xSDK != null ? aFi1xSDK.hashCode() : 0);
    }
}
