package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3435c3;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class A implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.n b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ A(androidx.compose.ui.n nVar, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = nVar;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.google.android.gms.common.wrappers.a.c(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 1:
                T2.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 2:
                com.google.android.gms.internal.mlkit_vision_common.A.b(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 3:
                AbstractC3429b3.a(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            case 4:
                AbstractC3435c3.a(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
            default:
                com.google.mlkit.common.model.a.h(C0776c.H(1), interfaceC0806l, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ A(Function0 function0, androidx.compose.ui.n nVar, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.b = nVar;
    }
}
