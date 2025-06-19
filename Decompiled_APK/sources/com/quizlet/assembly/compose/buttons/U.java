package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3626g5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class U implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ int d;

    public /* synthetic */ U(androidx.compose.ui.q qVar, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = qVar;
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
                AbstractC3594c5.a(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 1:
                AbstractC3626g5.b(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 2:
                com.google.common.util.concurrent.b.c(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 3:
                com.fasterxml.uuid.b.a(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 4:
                com.google.android.gms.internal.mlkit_vision_document_scanner.L.f(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 5:
                com.google.android.gms.internal.mlkit_vision_document_scanner.L.b(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 6:
                com.google.android.gms.internal.mlkit_vision_document_scanner.P.b(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 7:
                D6.l(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 8:
                D6.i(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 9:
                D6.f(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 10:
                E6.k(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 11:
                E6.h(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            case 12:
                AbstractC3215n6.g(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
            default:
                AbstractC3215n6.d(C0776c.H(this.d | 1), interfaceC0806l, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ U(Function0 function0, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.b = qVar;
        this.d = i;
    }
}
