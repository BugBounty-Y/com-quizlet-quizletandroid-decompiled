package com.quizlet.features.practicetest.detail.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ x b;
    public final /* synthetic */ n c;

    public /* synthetic */ d(x xVar, n nVar, int i, int i2) {
        this.a = i2;
        this.b = xVar;
        this.c = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                Y1.b(this.b, this.c, interfaceC0806l, C0776c.H(9));
                break;
            default:
                T2.a(this.b, this.c, interfaceC0806l, C0776c.H(9));
                break;
        }
        return Unit.a;
    }
}
