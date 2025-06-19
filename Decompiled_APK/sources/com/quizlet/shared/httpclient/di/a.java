package com.quizlet.shared.httpclient.di;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        org.koin.core.module.a module = (org.koin.core.module.a) obj;
        Intrinsics.checkNotNullParameter(module, "$this$module");
        return Unit.a;
    }
}
