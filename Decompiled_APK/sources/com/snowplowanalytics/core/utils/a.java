package com.snowplowanalytics.core.utils;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final /* synthetic */ int a = 0;

    public static final Object a(Object obj, String str, Object... objArr) {
        Class<?> cls = obj.getClass();
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        return cls.getMethod(str, null).invoke(obj, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
    }

    public static final Object b(String str, String str2, Class[] clsArr, Object... objArr) throws ClassNotFoundException {
        Class<?> classObject = Class.forName(str);
        Intrinsics.checkNotNullExpressionValue(classObject, "classObject");
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        return classObject.getMethod(str2, (Class[]) Arrays.copyOf(clsArr, clsArr.length)).invoke(null, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
    }
}
