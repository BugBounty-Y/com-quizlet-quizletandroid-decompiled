package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_common.O3;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ int c;

    public /* synthetic */ r(int i, int i2, androidx.compose.ui.q qVar) {
        this.a = 2;
        this.c = i;
        this.b = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.google.common.util.concurrent.b.a(C0776c.H(1), this.c, interfaceC0806l, this.b);
                break;
            case 1:
                AbstractC3180j7.a(C0776c.H(1), this.c, interfaceC0806l, this.b);
                break;
            case 2:
                O3.a(this.c, C0776c.H(1), interfaceC0806l, this.b);
                break;
            default:
                L5.f(C0776c.H(1), this.c, interfaceC0806l, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ r(androidx.compose.ui.q qVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = qVar;
        this.c = i2;
    }
}
