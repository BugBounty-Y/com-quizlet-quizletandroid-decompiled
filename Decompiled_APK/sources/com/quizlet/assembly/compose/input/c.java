package com.quizlet.assembly.compose.input;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3259s6;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ c(int i, int i2, Function0 function0, boolean z) {
        this.a = i2;
        this.b = function0;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3745v5.g(C0776c.H(7), interfaceC0806l, this.b, this.c);
                break;
            case 1:
                AbstractC3259s6.e(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 2:
                Y3.h(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            default:
                AbstractC3594c5.e(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(boolean z, Function0 function0, int i) {
        this.a = 2;
        this.c = z;
        this.b = function0;
    }
}
