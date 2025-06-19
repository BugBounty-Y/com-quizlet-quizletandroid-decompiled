package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class P4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0995g a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ androidx.compose.ui.text.font.j e;
    public final /* synthetic */ long f;
    public final /* synthetic */ androidx.compose.ui.text.style.i g;
    public final /* synthetic */ long h;
    public final /* synthetic */ int i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;
    public final /* synthetic */ Map m;
    public final /* synthetic */ Function1 n;
    public final /* synthetic */ androidx.compose.ui.text.L o;
    public final /* synthetic */ int p;
    public final /* synthetic */ int q;
    public final /* synthetic */ int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P4(C0995g c0995g, androidx.compose.ui.q qVar, long j, long j2, androidx.compose.ui.text.font.j jVar, long j3, androidx.compose.ui.text.style.i iVar, long j4, int i, boolean z, int i2, int i3, Map map, Function1 function1, androidx.compose.ui.text.L l, int i4, int i5, int i6) {
        super(2);
        this.a = c0995g;
        this.b = qVar;
        this.c = j;
        this.d = j2;
        this.e = jVar;
        this.f = j3;
        this.g = iVar;
        this.h = j4;
        this.i = i;
        this.j = z;
        this.k = i2;
        this.l = i3;
        this.m = map;
        this.n = function1;
        this.o = l;
        this.p = i4;
        this.q = i5;
        this.r = i6;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.p | 1);
        int iH2 = C0776c.H(this.q);
        Map map = this.m;
        int i = this.r;
        Q4.c(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, map, this.n, this.o, (InterfaceC0806l) obj, iH, iH2, i);
        return Unit.a;
    }
}
