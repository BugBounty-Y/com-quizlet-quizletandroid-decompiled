package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class X4 {
    public static final /* synthetic */ int a = 0;

    public static final assistantMode.enums.E c(assistantMode.enums.m mVar) {
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        int iOrdinal = mVar.ordinal();
        if (iOrdinal == 0) {
            return assistantMode.enums.E.b;
        }
        if (iOrdinal == 1) {
            return assistantMode.enums.E.c;
        }
        if (iOrdinal == 2) {
            return assistantMode.enums.E.d;
        }
        throw new NoWhenBranchMatchedException();
    }

    public abstract boolean a(androidx.compose.ui.modifier.h hVar);

    public abstract Object b(androidx.compose.ui.modifier.h hVar);
}
