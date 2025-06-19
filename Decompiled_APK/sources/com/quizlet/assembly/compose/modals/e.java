package com.quizlet.assembly.compose.modals;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_common.M2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3776z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.n c;

    public /* synthetic */ e(String str, androidx.compose.ui.n nVar, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                R5.b(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                R5.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                M2.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                AbstractC3776z4.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                G6.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                D0.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
