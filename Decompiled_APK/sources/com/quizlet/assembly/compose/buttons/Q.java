package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class Q implements Function2 {
    public static final Q a = new Q();

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        if ((((Number) obj2).intValue() & 3) == 2) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            if (c0814p.x()) {
                c0814p.Q();
            }
        }
        return Unit.a;
    }
}
