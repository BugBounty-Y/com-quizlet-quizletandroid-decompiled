package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class O2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ P2 a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function2 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ androidx.compose.ui.text.input.K f;
    public final /* synthetic */ androidx.compose.foundation.interaction.k g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ androidx.compose.runtime.internal.d i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;
    public final /* synthetic */ androidx.compose.runtime.internal.d l;
    public final /* synthetic */ androidx.compose.runtime.internal.d m;
    public final /* synthetic */ A4 n;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 o;
    public final /* synthetic */ androidx.compose.runtime.internal.d p;
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O2(P2 p2, String str, Function2 function2, boolean z, boolean z2, androidx.compose.ui.text.input.K k, androidx.compose.foundation.interaction.k kVar, boolean z3, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, A4 a4, androidx.compose.foundation.layout.A0 a0, androidx.compose.runtime.internal.d dVar6, int i) {
        super(2);
        this.a = p2;
        this.b = str;
        this.c = function2;
        this.d = z;
        this.e = z2;
        this.f = k;
        this.g = kVar;
        this.h = z3;
        this.i = dVar;
        this.j = dVar2;
        this.k = dVar3;
        this.l = dVar4;
        this.m = dVar5;
        this.n = a4;
        this.o = a0;
        this.p = dVar6;
        this.q = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.q | 1);
        androidx.compose.runtime.internal.d dVar = this.p;
        A4 a4 = this.n;
        this.a.b(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, a4, this.o, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
