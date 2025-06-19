package com.quizlet.features.notes.detail.composables.essay;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3736u4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;

    public /* synthetic */ a(boolean z, Object obj, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = obj;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.getClass();
                AbstractC3153g7.b(this.b, (q) this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 1:
                num.getClass();
                AbstractC3224o6.a(this.b, (q) this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                num.intValue();
                AbstractC3736u4.e(this.b, (Function1) this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
        }
        return Unit.a;
    }
}
