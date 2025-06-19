package com.quizlet.quizletandroid.ui.qrcodes.di;

import com.google.mlkit.vision.barcode.b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final b a;

    static {
        b bVar = new b(256);
        Intrinsics.checkNotNullExpressionValue(bVar, "build(...)");
        a = bVar;
    }
}
