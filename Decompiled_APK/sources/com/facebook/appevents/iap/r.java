package com.facebook.appevents.iap;

import java.lang.reflect.Method;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class r {
    public static final p g = new p();
    public static r h;
    public final Class a;
    public final Class b;
    public final Method c;
    public final Method d;
    public final Method e;
    public final Method f;

    public r(Class skuDetailsParamsClazz, Class builderClazz, Method newBuilderMethod, Method setTypeMethod, Method setSkusListMethod, Method buildMethod) {
        Intrinsics.checkNotNullParameter(skuDetailsParamsClazz, "skuDetailsParamsClazz");
        Intrinsics.checkNotNullParameter(builderClazz, "builderClazz");
        Intrinsics.checkNotNullParameter(newBuilderMethod, "newBuilderMethod");
        Intrinsics.checkNotNullParameter(setTypeMethod, "setTypeMethod");
        Intrinsics.checkNotNullParameter(setSkusListMethod, "setSkusListMethod");
        Intrinsics.checkNotNullParameter(buildMethod, "buildMethod");
        this.a = skuDetailsParamsClazz;
        this.b = builderClazz;
        this.c = newBuilderMethod;
        this.d = setTypeMethod;
        this.e = setSkusListMethod;
        this.f = buildMethod;
    }

    public final Object a(t productType, ArrayList arrayList) {
        Object objH;
        Object objH2;
        Class cls = this.b;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Intrinsics.checkNotNullParameter(productType, "productType");
                Object objH3 = u.h(this.a, null, this.c, new Object[0]);
                if (objH3 != null && (objH = u.h(cls, objH3, this.d, productType.a)) != null && (objH2 = u.h(cls, objH, this.e, arrayList)) != null) {
                    return u.h(cls, objH2, this.f, new Object[0]);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }
}
