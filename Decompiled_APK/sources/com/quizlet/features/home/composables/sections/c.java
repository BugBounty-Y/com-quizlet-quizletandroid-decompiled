package com.quizlet.features.home.composables.sections;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.collections.immutable.e;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ e b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ q d;

    public /* synthetic */ c(e eVar, q qVar, Function1 function1, int i) {
        this.b = eVar;
        this.d = qVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3205m5.b(C0776c.H(1), interfaceC0806l, this.d, this.c, this.b);
                break;
            default:
                Q1.e(C0776c.H(1), interfaceC0806l, this.d, this.c, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(e eVar, Function1 function1, q qVar, int i) {
        this.b = eVar;
        this.c = function1;
        this.d = qVar;
    }
}
