package com.sdk.growthbook.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ExtensionsKt {
    @NotNull
    public static final HashMap<String, Object> toHashMap(@NotNull v vVar) {
        Intrinsics.checkNotNullParameter(vVar, "<this>");
        HashMap<String, Object> map = new HashMap<>();
        for (Map.Entry entry : vVar.a.entrySet()) {
            String str = (String) entry.getKey();
            k kVar = (k) entry.getValue();
            if (kVar instanceof v) {
                map.put(str, toHashMap((v) kVar));
            } else if (kVar instanceof d) {
                map.put(str, toList((d) kVar));
            } else {
                map.put(str, l.h(kVar).a());
            }
        }
        return map;
    }

    @NotNull
    public static final k toJsonElement(@NotNull List<?> list) {
        ArrayList arrayListM = assistantMode.refactored.a.m("<this>", list);
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

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    public static final List<?> toList(@NotNull d dVar) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        ArrayList arrayList = new ArrayList();
        for (k kVar : dVar.a) {
            if (kVar instanceof v) {
                arrayList.add(toHashMap((v) kVar));
            } else if (kVar instanceof List) {
                arrayList.add(CollectionsKt.w0((Iterable) kVar));
            } else {
                arrayList.add(l.h(kVar).a());
            }
        }
        return arrayList;
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
