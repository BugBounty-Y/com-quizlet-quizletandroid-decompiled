package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3227p0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.j7;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;

    public /* synthetic */ c(androidx.compose.ui.q qVar, boolean z, Function1 function1, int i) {
        this.c = qVar;
        this.d = z;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                boolean z = this.d;
                j7.a(iH, interfaceC0806l, this.c, this.b, z);
                break;
            case 1:
                org.chromium.support_lib_boundary.util.a.e(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
            case 2:
                AbstractC3227p0.a(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
            default:
                AbstractC3625g4.e(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(Function1 function1, androidx.compose.ui.q qVar, boolean z, int i) {
        this.b = function1;
        this.c = qVar;
        this.d = z;
    }

    public /* synthetic */ c(boolean z, androidx.compose.ui.q qVar, Function1 function1, int i) {
        this.d = z;
        this.c = qVar;
        this.b = function1;
    }

    public /* synthetic */ c(boolean z, Function1 function1, androidx.compose.ui.q qVar, int i) {
        this.d = z;
        this.b = function1;
        this.c = qVar;
    }
}
