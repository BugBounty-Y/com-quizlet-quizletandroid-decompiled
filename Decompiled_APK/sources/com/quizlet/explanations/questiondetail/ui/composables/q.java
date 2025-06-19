package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class q implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ q(String str, Function1 function1, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = function1;
        this.d = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(433);
                com.google.common.util.concurrent.b.e(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(433);
                com.google.common.util.concurrent.b.d(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
