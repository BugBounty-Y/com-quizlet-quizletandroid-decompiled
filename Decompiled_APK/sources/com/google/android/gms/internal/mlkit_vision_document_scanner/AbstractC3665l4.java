package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.l4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3665l4 {
    public static final Object a(androidx.lifecycle.Y y) {
        Intrinsics.checkNotNullParameter(y, "<this>");
        if (y.d() == null) {
            throw new IllegalStateException("LiveData does not have any value");
        }
        Object objD = y.d();
        Intrinsics.d(objD);
        return objD;
    }
}
