package androidx.compose.foundation.text.modifiers;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.G;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.L;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class l extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ m b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(m mVar, int i) {
        super(1);
        this.a = i;
        this.b = mVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        H h = null;
        m mVar = this.b;
        switch (this.a) {
            case 0:
                List list = (List) obj;
                H h2 = mVar.N0().n;
                if (h2 != null) {
                    G g = h2.a;
                    h = new H(new G(g.a, L.f(mVar.o, C0861v.g, 0L, null, null, 0L, 0, 0L, 16777214), g.c, g.d, g.e, g.f, g.g, g.h, g.i, g.j), h2.b, h2.c);
                    list.add(h);
                }
                break;
            case 1:
                C0995g c0995g = (C0995g) obj;
                k kVar = mVar.C;
                if (kVar == null) {
                    k kVar2 = new k(mVar.n, c0995g);
                    d dVar = new d(c0995g, mVar.o, mVar.p, mVar.r, mVar.s, mVar.t, mVar.u, mVar.v);
                    dVar.c(mVar.N0().k);
                    kVar2.d = dVar;
                    mVar.C = kVar2;
                } else if (!Intrinsics.b(c0995g, kVar.b)) {
                    kVar.b = c0995g;
                    d dVar2 = kVar.d;
                    if (dVar2 != null) {
                        L l = mVar.o;
                        androidx.compose.ui.text.font.i iVar = mVar.p;
                        int i = mVar.r;
                        boolean z = mVar.s;
                        int i2 = mVar.t;
                        int i3 = mVar.u;
                        List list2 = mVar.v;
                        dVar2.a = c0995g;
                        dVar2.b = l;
                        dVar2.c = iVar;
                        dVar2.d = i;
                        dVar2.e = z;
                        dVar2.f = i2;
                        dVar2.g = i3;
                        dVar2.h = list2;
                        dVar2.l = null;
                        dVar2.n = null;
                        dVar2.p = -1;
                        dVar2.o = -1;
                        Unit unit = Unit.a;
                    }
                }
                AbstractC0910f.p(mVar);
                AbstractC0910f.o(mVar);
                AbstractC0910f.n(mVar);
                break;
            default:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                k kVar3 = mVar.C;
                if (kVar3 != null) {
                    Function1 function1 = mVar.y;
                    if (function1 != null) {
                        function1.invoke(kVar3);
                    }
                    k kVar4 = mVar.C;
                    if (kVar4 != null) {
                        kVar4.c = zBooleanValue;
                    }
                    AbstractC0910f.p(mVar);
                    AbstractC0910f.o(mVar);
                    AbstractC0910f.n(mVar);
                    break;
                } else {
                    break;
                }
        }
        return Boolean.TRUE;
    }
}
