package com.quizlet.ui.compose;

import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class U implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.ui.text.L f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ C4832z h;
    public final /* synthetic */ androidx.compose.foundation.shape.d i;
    public final /* synthetic */ C0555x j;
    public final /* synthetic */ float k;
    public final /* synthetic */ A0 l;
    public final /* synthetic */ androidx.compose.foundation.interaction.l m;
    public final /* synthetic */ androidx.compose.ui.q n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;

    public /* synthetic */ U(boolean z, Function0 function0, boolean z2, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar2, C4832z c4832z, androidx.compose.foundation.shape.d dVar3, C0555x c0555x, float f, A0 a0, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = z;
        this.c = function0;
        this.d = z2;
        this.e = dVar;
        this.f = l;
        this.g = dVar2;
        this.h = c4832z;
        this.i = dVar3;
        this.j = c0555x;
        this.k = f;
        this.l = a0;
        this.m = lVar;
        this.n = qVar;
        this.o = i;
        this.p = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.o | 1);
                int iH2 = C0776c.H(this.p);
                c0.c(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, interfaceC0806l, iH, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.o | 1);
                int iH4 = C0776c.H(this.p);
                c0.b(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, interfaceC0806l, iH3, iH4);
                break;
        }
        return Unit.a;
    }
}
