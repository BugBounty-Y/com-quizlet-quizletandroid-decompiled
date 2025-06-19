package com.snowplowanalytics.snowplow.payload;

import android.util.Base64;
import com.snowplowanalytics.core.tracker.e;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class b {
    public final String a = b.class.getSimpleName();
    public final HashMap b = new HashMap();

    public final void a(String key, String str) {
        Intrinsics.checkNotNullParameter(key, "key");
        HashMap map = this.b;
        String TAG = this.a;
        if (str == null || str.length() == 0) {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            e.e(TAG, "The keys value is empty, removing the key: %s", key);
            map.remove(key);
        } else {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            e.e(TAG, "Adding new kv pair: " + key + "->%s", str);
            map.put(key, str);
        }
    }

    public final void b(HashMap map, boolean z, String type_encoded, String type_no_encoded) {
        Intrinsics.checkNotNullParameter(map, "map");
        Intrinsics.checkNotNullParameter(type_encoded, "type_encoded");
        Intrinsics.checkNotNullParameter(type_no_encoded, "type_no_encoded");
        String string = new JSONObject(map).toString();
        Intrinsics.checkNotNullExpressionValue(string, "JSONObject(map).toString()");
        String TAG = this.a;
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        e.e(TAG, "Adding new map: %s", map);
        if (!z) {
            a(type_no_encoded, string);
            return;
        }
        Intrinsics.checkNotNullParameter(string, "string");
        byte[] bytes = string.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        String strEncodeToString = Base64.encodeToString(bytes, 2);
        Intrinsics.checkNotNullExpressionValue(strEncodeToString, "encodeToString(string.to…eArray(), Base64.NO_WRAP)");
        a(type_encoded, strEncodeToString);
    }

    public final void c(Map map) {
        Intrinsics.checkNotNullParameter(map, "map");
        String TAG = this.a;
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        e.e(TAG, "Adding new map: %s", map);
        for (Map.Entry entry : map.entrySet()) {
            String key = (String) entry.getKey();
            Object value = entry.getValue();
            Intrinsics.checkNotNullParameter(key, "key");
            HashMap map2 = this.b;
            if (value == null) {
                Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                e.e(TAG, "The value is empty, removing the key: %s", key);
                map2.remove(key);
            } else {
                Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                e.e(TAG, "Adding new kv pair: " + key + "->%s", value);
                map2.put(key, value);
            }
        }
    }

    public final long d() {
        long j;
        int i;
        String s = toString();
        Intrinsics.checkNotNullParameter(s, "s");
        long j2 = 0;
        int i2 = 0;
        while (i2 < s.length()) {
            char cCharAt = s.charAt(i2);
            if (cCharAt <= 127) {
                j = 1;
            } else {
                if (cCharAt <= 2047) {
                    i = 2;
                } else if (55296 <= cCharAt && cCharAt < 57344) {
                    j2 += 4;
                    i2++;
                    i2++;
                } else if (cCharAt < 65535) {
                    i = 3;
                } else {
                    j = 4;
                }
                j = i;
            }
            j2 += j;
            i2++;
        }
        return j2;
    }

    public final String toString() {
        HashMap map = this.b;
        Intrinsics.e(map, "null cannot be cast to non-null type kotlin.collections.Map<*, *>");
        String string = new JSONObject(map).toString();
        Intrinsics.checkNotNullExpressionValue(string, "JSONObject(map as Map<*, *>).toString()");
        return string;
    }
}
