package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ P2 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.foundation.interaction.k d;
    public final /* synthetic */ androidx.compose.ui.n e;
    public final /* synthetic */ A4 f;
    public final /* synthetic */ androidx.compose.ui.graphics.V g;
    public final /* synthetic */ float h;
    public final /* synthetic */ float i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N2(P2 p2, boolean z, boolean z2, androidx.compose.foundation.interaction.k kVar, androidx.compose.ui.n nVar, A4 a4, androidx.compose.ui.graphics.V v, float f, float f2, int i, int i2) {
        super(2);
        this.a = p2;
        this.b = z;
        this.c = z2;
        this.d = kVar;
        this.e = nVar;
        this.f = a4;
        this.g = v;
        this.h = f;
        this.i = f2;
        this.j = i;
        this.k = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        A4 a4 = this.f;
        androidx.compose.ui.graphics.V v = this.g;
        this.a.a(this.b, this.c, this.d, this.e, a4, v, this.h, this.i, (InterfaceC0806l) obj, iH, this.k);
        return Unit.a;
    }
}
