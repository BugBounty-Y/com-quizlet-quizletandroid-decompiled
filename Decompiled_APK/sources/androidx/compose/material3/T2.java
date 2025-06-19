package androidx.compose.material3;

import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ String a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.ui.text.L e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ androidx.camera.camera2.internal.s0 i;
    public final /* synthetic */ C0490g0 j;
    public final /* synthetic */ C0488f0 k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;
    public final /* synthetic */ androidx.compose.ui.graphics.V o;
    public final /* synthetic */ A4 p;
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T2(String str, Function1 function1, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.camera.camera2.internal.s0 s0Var, C0490g0 c0490g0, C0488f0 c0488f0, boolean z2, int i, int i2, androidx.compose.ui.graphics.V v, A4 a4, int i3) {
        super(2);
        this.a = str;
        this.b = function1;
        this.c = qVar;
        this.d = z;
        this.e = l;
        this.f = dVar;
        this.g = dVar2;
        this.h = dVar3;
        this.i = s0Var;
        this.j = c0490g0;
        this.k = c0488f0;
        this.l = z2;
        this.m = i;
        this.n = i2;
        this.o = v;
        this.p = a4;
        this.q = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.q | 1);
        A4 a4 = this.p;
        int i = this.m;
        int i2 = this.n;
        AbstractC0587a3.b(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, i, i2, this.o, a4, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
