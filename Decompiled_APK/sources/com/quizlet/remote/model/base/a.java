package com.quizlet.remote.model.base;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Function1 {
    public static final a a = new a();

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ApiResponse it2 = (ApiResponse) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2;
    }
}
