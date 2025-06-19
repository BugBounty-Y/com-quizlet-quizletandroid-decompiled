package androidx.compose.ui.layout;

import java.util.List;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class D extends androidx.compose.ui.node.C {
    public final /* synthetic */ G b;
    public final /* synthetic */ Function2 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(G g, Function2 function2, String str) {
        super(str);
        this.b = g;
        this.c = function2;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        G g = this.b;
        androidx.compose.ui.unit.k layoutDirection = m.getLayoutDirection();
        B b = g.h;
        b.a = layoutDirection;
        b.b = m.a();
        b.c = m.Z();
        boolean zA0 = m.a0();
        Function2 function2 = this.c;
        if (zA0 || g.a.c == null) {
            g.d = 0;
            L l = (L) function2.invoke(b, new androidx.compose.ui.unit.a(j));
            return new C(l, g, g.d, l, 1);
        }
        g.e = 0;
        L l2 = (L) function2.invoke(g.i, new androidx.compose.ui.unit.a(j));
        return new C(l2, g, g.e, l2, 0);
    }
}
