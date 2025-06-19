package org.koin.ext;

import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.c;

/* loaded from: classes3.dex */
public abstract class a {
    public static final ConcurrentHashMap a = new ConcurrentHashMap();

    public static final String a(c kClass) {
        Intrinsics.checkNotNullParameter(kClass, "<this>");
        ConcurrentHashMap concurrentHashMap = a;
        String str = (String) concurrentHashMap.get(kClass);
        if (str != null) {
            return str;
        }
        Intrinsics.checkNotNullParameter(kClass, "<this>");
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        String name = kotlin.jvm.a.b(kClass).getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        concurrentHashMap.put(kClass, name);
        return name;
    }
}
