package com.quizlet.ui.compose;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.ui.compose.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4811d implements Function2 {
    public static final C4811d b = new C4811d(0);
    public static final C4811d c = new C4811d(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C4811d(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
                if ((((Number) obj2).intValue() & 3) == 2) {
                    C0814p c0814p = (C0814p) interfaceC0806l;
                    if (c0814p.x()) {
                        c0814p.Q();
                    }
                }
                break;
            default:
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj;
                if ((((Number) obj2).intValue() & 3) == 2) {
                    C0814p c0814p2 = (C0814p) interfaceC0806l2;
                    if (c0814p2.x()) {
                        c0814p2.Q();
                    }
                }
                break;
        }
        return Unit.a;
    }
}
