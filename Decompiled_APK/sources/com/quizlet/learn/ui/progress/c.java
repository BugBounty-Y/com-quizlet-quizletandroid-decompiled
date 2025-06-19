package com.quizlet.learn.ui.progress;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ n c;

    public /* synthetic */ c(int i, n nVar, int i2, int i3) {
        this.a = i3;
        this.b = i;
        this.c = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                e.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3277v0.i(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
