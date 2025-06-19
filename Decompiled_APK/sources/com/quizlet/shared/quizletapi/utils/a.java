package com.quizlet.shared.quizletapi.utils;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return String.valueOf(((Number) obj).longValue());
    }
}
