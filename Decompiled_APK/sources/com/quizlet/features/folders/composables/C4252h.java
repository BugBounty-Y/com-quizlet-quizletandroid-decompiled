package com.quizlet.features.folders.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.E4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.composables.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4252h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ Function1 d;

    public /* synthetic */ C4252h(int i, int i2, androidx.compose.ui.q qVar, String str, Function1 function1) {
        this.a = i2;
        this.b = str;
        this.c = qVar;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                E4.a(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
            case 1:
                AbstractC3634h5.c(C0776c.H(49), interfaceC0806l, this.c, this.b, this.d);
                break;
            default:
                AbstractC3634h5.d(C0776c.H(1), interfaceC0806l, this.c, this.b, this.d);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4252h(androidx.compose.ui.q qVar, String str, Function1 function1, int i) {
        this.a = 2;
        this.c = qVar;
        this.b = str;
        this.d = function1;
    }
}
