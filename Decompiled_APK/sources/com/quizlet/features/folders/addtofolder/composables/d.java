package com.quizlet.features.folders.addtofolder.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_barcode.B0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    public /* synthetic */ d(int i, int i2, Function0 function0, androidx.compose.ui.q qVar, int i3) {
        this.c = i;
        this.e = i2;
        this.b = function0;
        this.d = qVar;
        this.f = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                Function0 function0 = this.b;
                B0.a(this.c, this.e, iH, (InterfaceC0806l) obj, this.d, function0);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                androidx.compose.ui.q qVar = this.d;
                int i = this.f;
                AbstractC3215n6.h(this.c, iH2, i, (InterfaceC0806l) obj, qVar, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(Function0 function0, int i, androidx.compose.ui.q qVar, int i2, int i3) {
        this.b = function0;
        this.c = i;
        this.d = qVar;
        this.e = i2;
        this.f = i3;
    }
}
