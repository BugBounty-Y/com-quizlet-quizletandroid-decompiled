package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.z1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3417z1 {
    public static final /* synthetic */ int a = 0;

    public static final Object[] a(Object[] objArr, int i, Object obj, Object obj2) {
        Object[] objArr2 = new Object[objArr.length + 2];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i + 2, objArr2, i, objArr.length);
        objArr2[i] = obj;
        objArr2[i + 1] = obj2;
        return objArr2;
    }

    public static final Object[] b(int i, Object[] objArr) {
        Object[] objArr2 = new Object[objArr.length - 2];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i, objArr2, i + 2, objArr.length);
        return objArr2;
    }

    public static final androidx.lifecycle.w0 c(androidx.lifecycle.C0 c0, C4950i modelClass, String key, androidx.lifecycle.y0 factory, androidx.lifecycle.viewmodel.c extras) {
        androidx.lifecycle.A0 a0P;
        if (factory != null) {
            androidx.lifecycle.B0 store = c0.getViewModelStore();
            Intrinsics.checkNotNullParameter(store, "store");
            Intrinsics.checkNotNullParameter(factory, "factory");
            Intrinsics.checkNotNullParameter(extras, "extras");
            a0P = new androidx.lifecycle.A0(store, factory, extras);
        } else if (c0 instanceof InterfaceC1261w) {
            androidx.lifecycle.B0 store2 = c0.getViewModelStore();
            androidx.lifecycle.y0 factory2 = ((InterfaceC1261w) c0).getDefaultViewModelProviderFactory();
            Intrinsics.checkNotNullParameter(store2, "store");
            Intrinsics.checkNotNullParameter(factory2, "factory");
            Intrinsics.checkNotNullParameter(extras, "extras");
            a0P = new androidx.lifecycle.A0(store2, factory2, extras);
        } else {
            a0P = com.google.mlkit.common.sdkinternal.model.a.p(c0, null, 6);
        }
        if (key == null) {
            return a0P.b(modelClass);
        }
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        return ((com.quizlet.data.repository.metering.j) a0P.a).e(modelClass, key);
    }

    public static final int d(int i, int i2) {
        return (i >> i2) & 31;
    }

    public static final androidx.lifecycle.w0 e(Class cls, androidx.lifecycle.C0 c0, String str, dagger.hilt.android.internal.lifecycle.f fVar, androidx.lifecycle.viewmodel.c cVar, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(cls, "<this>");
        return c(c0, kotlin.jvm.internal.K.a(cls), str, fVar, cVar);
    }
}
