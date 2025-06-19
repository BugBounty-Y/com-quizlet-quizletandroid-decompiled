package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3293x0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3301y0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ androidx.compose.ui.n c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ int e;

    public /* synthetic */ p(boolean z, androidx.compose.ui.n nVar, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = nVar;
        this.d = function0;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(this.e | 1);
                AbstractC3293x0.c(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(this.e | 1);
                AbstractC3301y0.b(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
