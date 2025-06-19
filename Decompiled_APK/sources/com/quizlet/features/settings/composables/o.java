package com.quizlet.features.settings.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.I2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class o implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.settings.data.states.y b;
    public final /* synthetic */ n c;
    public final /* synthetic */ androidx.compose.ui.n d;

    public /* synthetic */ o(com.quizlet.features.settings.data.states.y yVar, n nVar, androidx.compose.ui.n nVar2, int i, int i2) {
        this.a = i2;
        this.b = yVar;
        this.c = nVar;
        this.d = nVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                I2.e(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                I2.d(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
