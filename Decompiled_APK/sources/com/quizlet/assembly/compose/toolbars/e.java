package com.quizlet.assembly.compose.toolbars;

import androidx.compose.foundation.layout.H0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements kotlin.jvm.functions.c {
    public static final e b = new e(0);
    public static final e c = new e(1);
    public static final e d = new e(2);
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                int iIntValue = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter((H0) obj, "<this>");
                if ((iIntValue & 17) == 16) {
                    C0814p c0814p = (C0814p) interfaceC0806l;
                    if (c0814p.x()) {
                        c0814p.Q();
                    }
                }
                break;
            case 1:
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                int iIntValue2 = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter((H0) obj, "<this>");
                if ((iIntValue2 & 17) == 16) {
                    C0814p c0814p2 = (C0814p) interfaceC0806l2;
                    if (c0814p2.x()) {
                        c0814p2.Q();
                    }
                }
                break;
            default:
                InterfaceC0806l interfaceC0806l3 = (InterfaceC0806l) obj2;
                int iIntValue3 = ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter((H0) obj, "<this>");
                if ((iIntValue3 & 17) == 16) {
                    C0814p c0814p3 = (C0814p) interfaceC0806l3;
                    if (c0814p3.x()) {
                        c0814p3.Q();
                    }
                }
                break;
        }
        return Unit.a;
    }
}
