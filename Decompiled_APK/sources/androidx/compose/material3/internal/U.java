package androidx.compose.material3.internal;

import androidx.compose.foundation.layout.A0;
import androidx.compose.material3.A4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class U extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Z a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function2 c;
    public final /* synthetic */ androidx.compose.ui.text.input.K d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ androidx.compose.runtime.internal.d i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ androidx.compose.foundation.interaction.k m;
    public final /* synthetic */ A0 n;
    public final /* synthetic */ A4 o;
    public final /* synthetic */ androidx.compose.runtime.internal.d p;
    public final /* synthetic */ int q;
    public final /* synthetic */ int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(Z z, String str, Function2 function2, androidx.compose.ui.text.input.K k, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, boolean z2, boolean z3, boolean z4, androidx.compose.foundation.interaction.k kVar, A0 a0, A4 a4, androidx.compose.runtime.internal.d dVar6, int i, int i2) {
        super(2);
        this.a = z;
        this.b = str;
        this.c = function2;
        this.d = k;
        this.e = dVar;
        this.f = dVar2;
        this.g = dVar3;
        this.h = dVar4;
        this.i = dVar5;
        this.j = z2;
        this.k = z3;
        this.l = z4;
        this.m = kVar;
        this.n = a0;
        this.o = a4;
        this.p = dVar6;
        this.q = i;
        this.r = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.q | 1);
        int iH2 = C0776c.H(this.r);
        A4 a4 = this.o;
        Z z = this.a;
        androidx.compose.foundation.interaction.k kVar = this.m;
        A0 a0 = this.n;
        Y.a(z, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, kVar, a0, a4, this.p, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
