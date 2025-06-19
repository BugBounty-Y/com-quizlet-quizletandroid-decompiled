package com.quizlet.offline;

import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements h {
    public static final b a = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean isLoggedOut = (Boolean) obj;
        Intrinsics.checkNotNullParameter(isLoggedOut, "isLoggedOut");
        return isLoggedOut.booleanValue() ? p.f(a.b) : p.f(a.a);
    }
}
