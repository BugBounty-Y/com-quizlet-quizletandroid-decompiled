package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class O4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ String a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ androidx.compose.ui.text.font.u e;
    public final /* synthetic */ long f;
    public final /* synthetic */ androidx.compose.ui.text.style.i g;
    public final /* synthetic */ long h;
    public final /* synthetic */ int i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ androidx.compose.ui.text.L n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O4(String str, androidx.compose.ui.q qVar, long j, long j2, androidx.compose.ui.text.font.u uVar, long j3, androidx.compose.ui.text.style.i iVar, long j4, int i, boolean z, int i2, int i3, Function1 function1, androidx.compose.ui.text.L l, int i4, int i5, int i6) {
        super(2);
        this.a = str;
        this.b = qVar;
        this.c = j;
        this.d = j2;
        this.e = uVar;
        this.f = j3;
        this.g = iVar;
        this.h = j4;
        this.i = i;
        this.j = z;
        this.k = i2;
        this.l = i3;
        this.m = function1;
        this.n = l;
        this.o = i4;
        this.p = i5;
        this.q = i6;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.o | 1);
        int iH2 = C0776c.H(this.p);
        int i = this.l;
        int i2 = this.q;
        Q4.b(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, i, this.m, this.n, (InterfaceC0806l) obj, iH, iH2, i2);
        return Unit.a;
    }
}
