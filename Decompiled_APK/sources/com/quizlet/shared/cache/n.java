package com.quizlet.shared.cache;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class n extends kotlin.jvm.internal.r implements Function2 {
    public static final n a = new n(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        org.koin.core.scope.a factory = (org.koin.core.scope.a) obj;
        org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
        Intrinsics.checkNotNullParameter(factory, "$this$factory");
        Intrinsics.checkNotNullParameter(it2, "it");
        return new com.quizlet.shared.repository.folderstudymaterials.a(new com.quizlet.quizletandroid.logging.initializer.a(6), (a) factory.a(null, K.a(a.class), AbstractC3410x2.b("persistent")));
    }
}
