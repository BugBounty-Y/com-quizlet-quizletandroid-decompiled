package com.quizlet.ui.compose;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class T implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.ui.text.L e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ S g;
    public final /* synthetic */ androidx.compose.foundation.shape.d h;
    public final /* synthetic */ float i;
    public final /* synthetic */ A0 j;
    public final /* synthetic */ androidx.compose.foundation.interaction.l k;
    public final /* synthetic */ androidx.compose.ui.q l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;

    public /* synthetic */ T(Function0 function0, boolean z, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar2, S s, androidx.compose.foundation.shape.d dVar3, float f, A0 a0, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = function0;
        this.c = z;
        this.d = dVar;
        this.e = l;
        this.f = dVar2;
        this.g = s;
        this.h = dVar3;
        this.i = f;
        this.j = a0;
        this.k = lVar;
        this.l = qVar;
        this.m = i;
        this.n = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.m | 1);
                int iH2 = C0776c.H(this.n);
                c0.f(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.m | 1);
                int iH4 = C0776c.H(this.n);
                c0.d(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, interfaceC0806l, iH3, iH4);
                break;
        }
        return Unit.a;
    }
}
