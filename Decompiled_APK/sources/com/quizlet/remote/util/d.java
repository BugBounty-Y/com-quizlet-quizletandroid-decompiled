package com.quizlet.remote.util;

import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.b {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.b
    public final Object apply(Object obj, Object obj2) {
        List first = (List) obj;
        List second = (List) obj2;
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        return CollectionsKt.c0(first, second);
    }
}
