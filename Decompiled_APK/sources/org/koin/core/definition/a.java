package org.koin.core.definition;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        kotlin.reflect.c it2 = (kotlin.reflect.c) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return org.koin.ext.a.a(it2);
    }
}
