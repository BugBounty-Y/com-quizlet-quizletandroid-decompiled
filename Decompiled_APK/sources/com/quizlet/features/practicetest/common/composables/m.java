package com.quizlet.features.practicetest.common.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.transition.C1412o;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class m implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.e b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ m(kotlinx.collections.immutable.e eVar, Function1 function1, Function0 function0, int i, int i2) {
        this.a = i2;
        this.b = eVar;
        this.c = function1;
        this.d = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                U1.b(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                C1412o.d(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
