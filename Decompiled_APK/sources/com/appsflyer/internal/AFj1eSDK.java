package com.appsflyer.internal;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.C;
import kotlin.collections.P;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.sequences.n;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFj1eSDK {
    private static final Object AFAdRevenueData(Object obj) {
        if (obj instanceof JSONArray) {
            return getCurrencyIso4217Code((JSONArray) obj);
        }
        if (obj instanceof JSONObject) {
            return getCurrencyIso4217Code((JSONObject) obj);
        }
        if (Intrinsics.b(obj, JSONObject.NULL)) {
            return null;
        }
        return obj;
    }

    @NotNull
    public static final Map<String, Object> getCurrencyIso4217Code(@NotNull JSONObject jSONObject) throws JSONException {
        Intrinsics.checkNotNullParameter(jSONObject, "");
        Iterator<String> itKeys = jSONObject.keys();
        Intrinsics.checkNotNullExpressionValue(itKeys, "");
        kotlin.sequences.a aVarB = n.b(itKeys);
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = aVarB.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            Object obj = jSONObject.get((String) next);
            Intrinsics.checkNotNullExpressionValue(obj, "");
            linkedHashMap.put(next, AFAdRevenueData(obj));
        }
        return linkedHashMap;
    }

    private static final List<Object> getCurrencyIso4217Code(JSONArray jSONArray) throws JSONException {
        IntRange intRangeH = kotlin.ranges.l.h(0, jSONArray.length());
        ArrayList arrayList = new ArrayList(C.q(intRangeH, 10));
        Iterator it2 = intRangeH.iterator();
        while (it2.hasNext()) {
            Object obj = jSONArray.get(((P) it2).nextInt());
            Intrinsics.checkNotNullExpressionValue(obj, "");
            arrayList.add(AFAdRevenueData(obj));
        }
        return arrayList;
    }
}
