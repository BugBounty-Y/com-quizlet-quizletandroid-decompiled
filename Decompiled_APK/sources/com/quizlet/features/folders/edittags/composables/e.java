package com.quizlet.features.folders.edittags.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ q d;
    public final /* synthetic */ int e;

    public /* synthetic */ e(boolean z, q qVar, Function0 function0, int i) {
        this.b = z;
        this.d = qVar;
        this.c = function0;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                V4.g(C0776c.H(this.e | 1), interfaceC0806l, this.d, this.c, this.b);
                break;
            default:
                Y3.d(C0776c.H(this.e | 1), interfaceC0806l, this.d, this.c, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(boolean z, Function0 function0, q qVar, int i) {
        this.b = z;
        this.c = function0;
        this.d = qVar;
        this.e = i;
    }
}
