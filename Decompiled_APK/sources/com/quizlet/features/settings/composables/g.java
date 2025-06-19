package com.quizlet.features.settings.composables;

import androidx.compose.foundation.layout.H0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements kotlin.jvm.functions.c {
    public static final g a = new g();

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
        int iIntValue = ((Number) obj3).intValue();
        Intrinsics.checkNotNullParameter((H0) obj, "<this>");
        if ((iIntValue & 17) == 16) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            if (c0814p.x()) {
                c0814p.Q();
            }
        }
        return Unit.a;
    }
}
