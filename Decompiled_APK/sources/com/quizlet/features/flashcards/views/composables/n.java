package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3285w0;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.quizlet.features.notes.data.y;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ n(int i, int i2, q qVar, Function0 function0, Function0 function02, int i3, int i4) {
        this.b = i;
        this.c = i2;
        this.f = qVar;
        this.d = function0;
        this.g = function02;
        this.e = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(27649);
                AbstractC3285w0.c(this.b, this.c, (q) this.f, this.d, (Function0) this.g, this.e, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(this.e | 1);
                C7.a(this.b, this.c, (y) this.f, (androidx.compose.ui.n) this.g, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ n(int i, int i2, y yVar, androidx.compose.ui.n nVar, Function0 function0, int i3) {
        this.b = i;
        this.c = i2;
        this.f = yVar;
        this.g = nVar;
        this.d = function0;
        this.e = i3;
    }
}
