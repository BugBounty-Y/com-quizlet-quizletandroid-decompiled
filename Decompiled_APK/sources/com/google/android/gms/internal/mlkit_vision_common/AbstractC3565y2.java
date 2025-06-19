package com.google.android.gms.internal.mlkit_vision_common;

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArraySet;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.y2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3565y2 {
    public static final /* synthetic */ int a = 0;

    public static void a(JSONObject jSONObject) {
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String key = itKeys.next();
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject(key);
            if (jSONObjectOptJSONObject != null) {
                String k = jSONObjectOptJSONObject.optString("k");
                String v = jSONObjectOptJSONObject.optString("v");
                Intrinsics.checkNotNullExpressionValue(k, "k");
                if (k.length() != 0) {
                    CopyOnWriteArraySet copyOnWriteArraySetA = com.facebook.appevents.aam.c.a();
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    List listSplit$default = StringsKt__StringsKt.split$default(k, new String[]{","}, false, 0, 6, null);
                    Intrinsics.checkNotNullExpressionValue(v, "v");
                    copyOnWriteArraySetA.add(new com.facebook.appevents.aam.c(key, v, listSplit$default));
                }
            }
        }
    }
}
