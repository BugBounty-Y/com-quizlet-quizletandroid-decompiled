package com.google.android.gms.internal.mlkit_vision_camera;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A2 {
    public static final /* synthetic */ int a = 0;

    public static final androidx.work.impl.model.j a(androidx.work.impl.model.q qVar) {
        Intrinsics.checkNotNullParameter(qVar, "<this>");
        return new androidx.work.impl.model.j(qVar.a, qVar.t);
    }

    public static org.koin.core.module.a b(Function1 moduleDeclaration) {
        Intrinsics.checkNotNullParameter(moduleDeclaration, "moduleDeclaration");
        org.koin.core.module.a aVar = new org.koin.core.module.a();
        moduleDeclaration.invoke(aVar);
        return aVar;
    }
}
