package com.quizlet.assembly.compose.listitems;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.skydoves.balloon.compose.BalloonKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ Function2 c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;

    public /* synthetic */ c(androidx.compose.ui.q qVar, Function2 function2, int i, int i2, int i3) {
        this.a = i3;
        this.b = qVar;
        this.c = function2;
        this.d = i;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.d | 1);
                Function2 function2 = this.c;
                int i = this.e;
                B5.d(this.b, function2, (InterfaceC0806l) obj, iH, i);
                return Unit.a;
            default:
                int iIntValue = ((Integer) obj2).intValue();
                int i2 = this.d;
                int i3 = this.e;
                return BalloonKt.BalloonLayout$lambda$34(this.b, this.c, i2, i3, (InterfaceC0806l) obj, iIntValue);
        }
    }
}
