package com.sdk.growthbook.network;

import assistantMode.refactored.a;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBNetworkDispatcherOkHttpKt {
    @NotNull
    public static final k toJsonElement(@NotNull List<?> list) {
        ArrayList arrayListM = a.m("<this>", list);
        for (Object obj : list) {
            if (obj != null) {
                if (obj instanceof Map) {
                    arrayListM.add(toJsonElement((Map<?, ?>) obj));
                } else if (obj instanceof List) {
                    arrayListM.add(toJsonElement((List<?>) obj));
                } else if (obj instanceof Boolean) {
                    arrayListM.add(l.a((Boolean) obj));
                } else if (obj instanceof Number) {
                    arrayListM.add(l.b((Number) obj));
                } else {
                    arrayListM.add(l.c(obj.toString()));
                }
            }
        }
        return new d(arrayListM);
    }

    @NotNull
    public static final k toJsonElement(@NotNull Map<?, ?> map) {
        Object value;
        Object objB;
        Intrinsics.checkNotNullParameter(map, "<this>");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            String str = key instanceof String ? (String) key : null;
            if (str != null && (value = entry.getValue()) != null) {
                if (value instanceof Map) {
                    objB = toJsonElement((Map<?, ?>) value);
                } else if (value instanceof List) {
                    objB = toJsonElement((List<?>) value);
                } else if (value instanceof Boolean) {
                    objB = l.a((Boolean) value);
                } else {
                    objB = value instanceof Number ? l.b((Number) value) : l.c(value.toString());
                }
                linkedHashMap.put(str, objB);
            }
        }
        return new v(linkedHashMap);
    }
}
