package androidx.compose.material;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.X0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.ui.graphics.V b;
    public final /* synthetic */ long c;
    public final /* synthetic */ float d;
    public final /* synthetic */ float e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h0(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, float f, float f2, androidx.compose.runtime.internal.d dVar) {
        super(2);
        this.a = qVar;
        this.b = v;
        this.c = j;
        this.d = f;
        this.e = f2;
        this.f = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        int iIntValue = ((Number) obj2).intValue();
        C0814p c0814p = (C0814p) interfaceC0806l;
        if (c0814p.N(iIntValue & 1, (iIntValue & 3) != 2)) {
            C0580x c0580x = (C0580x) c0814p.j(A.a);
            X0 x0 = AbstractC0578v.a;
            long jA = ((C0576t) c0814p.j(x0)).a();
            long jM = this.c;
            if (!C0861v.c(jM, jA) || c0580x == null) {
                c0814p.X(1082990783);
                c0814p.p(false);
            } else {
                c0814p.X(1082922676);
                c0814p.X(-1687113661);
                C0576t c0576t = (C0576t) c0814p.j(x0);
                if (Float.compare(this.d, 0) <= 0 || ((Boolean) ((L0) c0576t.m).getValue()).booleanValue()) {
                    c0814p.X(1169156439);
                    c0814p.p(false);
                } else {
                    c0814p.X(1169017931);
                    jM = androidx.compose.ui.graphics.F.m(C0861v.b(AbstractC0578v.a(jM, c0814p), ((((float) Math.log(r4 + 1)) * 4.5f) + 2.0f) / 100.0f), jM);
                    c0814p.p(false);
                }
                c0814p.p(false);
                c0814p.p(false);
            }
            androidx.compose.ui.q qVar = this.a;
            float f = this.e;
            androidx.compose.ui.graphics.V v = this.b;
            androidx.compose.ui.q qVarA = androidx.compose.ui.input.pointer.v.a(androidx.compose.ui.semantics.m.a(androidx.compose.ui.draw.g.c(AbstractC0460p.f(androidx.compose.ui.draw.g.j(qVar, f, v, 24).g(androidx.compose.ui.n.b), jM, v), v), false, Y.c), Unit.a, new g0(2, null));
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, true);
            int i = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarA);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i))) {
                android.support.v4.media.session.a.z(i, c0814p, i, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            this.f.invoke(c0814p, 0);
            c0814p.p(true);
        } else {
            c0814p.Q();
        }
        return Unit.a;
    }
}
