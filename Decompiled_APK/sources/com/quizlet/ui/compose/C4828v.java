package com.quizlet.ui.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.ui.compose.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4828v implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ float b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ int e;

    public /* synthetic */ C4828v(float f, boolean z, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.b = f;
        this.c = z;
        this.d = qVar;
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
                AbstractC3274u5.a(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(this.e | 1);
                AbstractC3274u5.c(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
