package com.quizlet.report.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import com.quizlet.report.data.o;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ o b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ c(o oVar, Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = oVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3119d0.g(this.b, this.c, interfaceC0806l, C0776c.H(7));
                break;
            case 1:
                AbstractC3119d0.f(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3119d0.b(this.b, this.c, interfaceC0806l, C0776c.H(7));
                break;
        }
        return Unit.a;
    }
}
