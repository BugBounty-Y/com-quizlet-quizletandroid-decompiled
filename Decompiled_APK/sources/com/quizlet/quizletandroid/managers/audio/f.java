package com.quizlet.quizletandroid.managers.audio;

import io.reactivex.rxjava3.functions.i;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements i, io.reactivex.rxjava3.functions.h {
    public static final f a = new f();
    public static final f b = new f();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        File it2 = (File) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.exists() ? io.reactivex.rxjava3.core.g.c(it2) : io.reactivex.rxjava3.internal.operators.maybe.f.a;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Intrinsics.checkNotNullParameter((Throwable) obj, "<unused var>");
        return true;
    }
}
