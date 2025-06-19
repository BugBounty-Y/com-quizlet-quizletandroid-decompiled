package com.quizlet.quizletandroid.ui.common.images.loading.glide;

import io.reactivex.rxjava3.functions.h;
import java.io.File;
import java.io.FileInputStream;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements h {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        File file = (File) obj;
        Intrinsics.checkNotNullParameter(file, "file");
        return new FileInputStream(file);
    }
}
