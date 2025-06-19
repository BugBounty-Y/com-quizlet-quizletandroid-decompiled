package androidx.compose.foundation;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.gestures.InterfaceC0314a0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;

/* loaded from: classes.dex */
public final class I0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ N0 a;
    public final /* synthetic */ InterfaceC0314a0 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I0(N0 n0, InterfaceC0314a0 interfaceC0314a0, boolean z, boolean z2) {
        super(3);
        this.a = n0;
        this.b = interfaceC0314a0;
        this.c = z;
        this.d = z2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(1478351300);
        N0 n0 = this.a;
        InterfaceC0314a0 interfaceC0314a0 = this.b;
        boolean z = this.c;
        boolean z2 = this.d;
        androidx.compose.ui.q qVarG = AbstractC0460p.s(new ScrollSemanticsElement(n0, interfaceC0314a0, z, z2), n0, z2 ? EnumC0320d0.a : EnumC0320d0.b, z, interfaceC0314a0, n0.c, null, c0814p, 64).g(new ScrollingLayoutElement(n0, z2));
        c0814p.p(false);
        return qVarG;
    }
}
