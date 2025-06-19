package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3642i5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class e0 implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.ui.n b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ int d;

    public /* synthetic */ e0(androidx.compose.ui.n nVar, Function0 function0, int i) {
        this.b = nVar;
        this.c = function0;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3642i5.a(this.d, C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            default:
                L2.d(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e0(androidx.compose.ui.n nVar, Function0 function0, int i, int i2) {
        this.d = i;
        this.b = nVar;
        this.c = function0;
    }
}
