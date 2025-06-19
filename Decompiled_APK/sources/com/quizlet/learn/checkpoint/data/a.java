package com.quizlet.learn.checkpoint.data;

import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Pair pair = (Pair) obj;
        Intrinsics.checkNotNullParameter(pair, "<destruct>");
        return (List) pair.b;
    }
}
