package com.quizlet.features.folders.changetags.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3144f7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3549v4;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ n b;

    public /* synthetic */ a(n nVar, int i, int i2) {
        this.a = i2;
        this.b = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3313z4.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                R5.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                AbstractC3144f7.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                F2.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                AbstractC3549v4.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            default:
                C.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
