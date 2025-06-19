package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3383q2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3398u2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class k implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ k(q qVar, Function0 function0, Function0 function02, int i) {
        this.a = 1;
        this.b = qVar;
        this.c = function0;
        this.d = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3277v0.l(C0776c.H(439), interfaceC0806l, this.b, this.c, this.d);
                break;
            case 1:
                AbstractC3340g.a(C0776c.H(1), interfaceC0806l, this.b, this.c, this.d);
                break;
            case 2:
                AbstractC3383q2.a(C0776c.H(1), interfaceC0806l, this.b, this.c, this.d);
                break;
            default:
                AbstractC3398u2.a(C0776c.H(1), interfaceC0806l, this.b, this.c, this.d);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ k(Function0 function0, Function0 function02, q qVar, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.d = function02;
        this.b = qVar;
    }
}
