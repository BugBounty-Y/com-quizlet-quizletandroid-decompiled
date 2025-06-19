package com.quizlet.features.settings.composables.changetheme;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_common.Q2;
import com.google.android.gms.internal.mlkit_vision_common.R2;
import com.quizlet.features.settings.viewmodels.m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ H b;
    public final /* synthetic */ m c;

    public /* synthetic */ b(H h, m mVar, int i, int i2) {
        this.a = i2;
        this.b = h;
        this.c = mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                Q2.a(this.b, this.c, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                R2.a(this.b, this.c, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
