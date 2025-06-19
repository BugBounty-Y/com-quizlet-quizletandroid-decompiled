package com.features.flashcards.creatormarketing;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.ads.internal.util.G;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3250r6;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_common.M2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3611e6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ b(q qVar, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = qVar;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                M2.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 1:
                com.google.mlkit.vision.common.internal.c.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 2:
                O4.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 3:
                V4.f(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 4:
                G.a(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 5:
                J.a(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 6:
                AbstractC3611e6.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            default:
                AbstractC3250r6.a(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ b(Function0 function0, q qVar, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.b = qVar;
    }
}
