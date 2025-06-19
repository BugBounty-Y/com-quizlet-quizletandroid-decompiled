package com.quizlet.shared.models.api.di;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function2 {
    public static final a a = new a(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
        org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
        Intrinsics.checkNotNullParameter(single, "$this$single");
        Intrinsics.checkNotNullParameter(it2, "it");
        return com.quizlet.shared.models.api.a.b;
    }
}
