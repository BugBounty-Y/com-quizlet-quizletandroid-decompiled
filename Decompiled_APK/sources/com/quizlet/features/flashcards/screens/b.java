package com.quizlet.features.flashcards.screens;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.A0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3423a3;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ int c;

    public /* synthetic */ b(int i, int i2, Function0 function0) {
        this.a = i2;
        this.b = function0;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.intValue();
                AbstractC3173j0.e(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 1:
                num.intValue();
                AbstractC3142f5.a(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 2:
                num.intValue();
                L2.c(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 3:
                num.getClass();
                AbstractC3423a3.a(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 4:
                num.getClass();
                AbstractC3423a3.b(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 5:
                num.intValue();
                L.c(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 6:
                num.intValue();
                A0.b(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            case 7:
                num.intValue();
                AbstractC3215n6.b(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            default:
                num.intValue();
                AbstractC3215n6.c(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
        }
        return Unit.a;
    }
}
