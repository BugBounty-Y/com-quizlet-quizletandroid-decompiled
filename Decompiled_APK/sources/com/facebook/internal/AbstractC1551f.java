package com.facebook.internal;

import android.os.Bundle;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.facebook.internal.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1551f {
    public static final HashMap a;

    static {
        HashMap map = new HashMap();
        a = map;
        map.put(Boolean.class, new C1550e(0));
        map.put(Integer.class, new C1550e(1));
        map.put(Long.class, new C1550e(2));
        map.put(Double.class, new C1550e(3));
        map.put(String.class, new C1550e(4));
        map.put(String[].class, new C1550e(5));
        map.put(JSONArray.class, new C1550e(6));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final Bundle a(JSONObject jsonObject) throws JSONException {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Bundle bundle = new Bundle();
        Iterator<String> itKeys = jsonObject.keys();
        while (itKeys.hasNext()) {
            String key = itKeys.next();
            Object value = jsonObject.get(key);
            if (value != JSONObject.NULL) {
                if (!(value instanceof JSONObject)) {
                    C1550e c1550e = (C1550e) a.get(value.getClass());
                    if (c1550e == null) {
                        throw new IllegalArgumentException("Unsupported type: " + value.getClass());
                    }
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    switch (c1550e.a) {
                        case 0:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            bundle.putBoolean(key, ((Boolean) value).booleanValue());
                            break;
                        case 1:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            bundle.putInt(key, ((Integer) value).intValue());
                            break;
                        case 2:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            bundle.putLong(key, ((Long) value).longValue());
                            break;
                        case 3:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            bundle.putDouble(key, ((Double) value).doubleValue());
                            break;
                        case 4:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            bundle.putString(key, (String) value);
                            break;
                        case 5:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            throw new IllegalArgumentException("Unexpected type from JSON");
                        default:
                            Intrinsics.checkNotNullParameter(bundle, "bundle");
                            Intrinsics.checkNotNullParameter(key, "key");
                            Intrinsics.checkNotNullParameter(value, "value");
                            JSONArray jSONArray = (JSONArray) value;
                            ArrayList arrayList = new ArrayList();
                            if (jSONArray.length() == 0) {
                                bundle.putStringArrayList(key, arrayList);
                                break;
                            } else {
                                int length = jSONArray.length();
                                for (int i = 0; i < length; i++) {
                                    Object obj = jSONArray.get(i);
                                    if (!(obj instanceof String)) {
                                        throw new IllegalArgumentException("Unexpected type in an array: " + obj.getClass());
                                    }
                                    arrayList.add(obj);
                                }
                                bundle.putStringArrayList(key, arrayList);
                                break;
                            }
                    }
                } else {
                    bundle.putBundle(key, a((JSONObject) value));
                }
            }
        }
        return bundle;
    }
}
