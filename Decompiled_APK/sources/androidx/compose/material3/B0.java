package androidx.compose.material3;

import androidx.compose.foundation.C0367i0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0657v;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class B0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ long a;
    public final /* synthetic */ InterfaceC0773a0 b;
    public final /* synthetic */ kotlinx.coroutines.C c;
    public final /* synthetic */ androidx.compose.foundation.lazy.A d;
    public final /* synthetic */ IntRange e;
    public final /* synthetic */ C0657v f;
    public final /* synthetic */ InterfaceC0764y3 g;
    public final /* synthetic */ AbstractC0655t h;
    public final /* synthetic */ C0699p0 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B0(long j, InterfaceC0773a0 interfaceC0773a0, kotlinx.coroutines.C c, androidx.compose.foundation.lazy.A a, IntRange intRange, C0657v c0657v, InterfaceC0764y3 interfaceC0764y3, AbstractC0655t abstractC0655t, C0699p0 c0699p0) {
        super(3);
        this.a = j;
        this.b = interfaceC0773a0;
        this.c = c;
        this.d = a;
        this.e = intRange;
        this.f = c0657v;
        this.g = interfaceC0764y3;
        this.h = abstractC0655t;
        this.i = c0699p0;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        IntRange intRange;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
        ((Number) obj3).intValue();
        String strG = AbstractC0646j.g(interfaceC0806l, R.string.m3c_date_picker_year_picker_pane_title);
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zF = c0814p.f(strG);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zF || objI == v) {
            objI = new C0367i0(strG, 3);
            c0814p.i0(objI);
        }
        androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(nVar, false, (Function1) objI);
        androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
        C0776c.E(c0814p, bA, C0914j.f);
        C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
        C0912h c0912h = C0914j.g;
        if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i))) {
            android.support.v4.media.session.a.z(i, c0814p, i, c0912h);
        }
        C0776c.E(c0814p, qVarC, C0914j.d);
        androidx.compose.ui.q qVarW = AbstractC0382e.w(androidx.compose.foundation.layout.K0.g(nVar, (Z0.a * 7) - AbstractC0621g1.a), Z0.c, DefinitionKt.NO_Float_VALUE, 2);
        InterfaceC0773a0 interfaceC0773a0 = this.b;
        boolean zF2 = c0814p.f(interfaceC0773a0);
        kotlinx.coroutines.C c = this.c;
        boolean zH = zF2 | c0814p.h(c);
        androidx.compose.foundation.lazy.A a = this.d;
        boolean zF3 = zH | c0814p.f(a);
        IntRange intRange2 = this.e;
        boolean zH2 = zF3 | c0814p.h(intRange2);
        C0657v c0657v = this.f;
        boolean zF4 = zH2 | c0814p.f(c0657v);
        Object objI2 = c0814p.I();
        if (zF4 || objI2 == v) {
            androidx.activity.compose.d dVar = new androidx.activity.compose.d(c, interfaceC0773a0, a, intRange2, c0657v);
            intRange = intRange2;
            c0814p.i0(dVar);
            objI2 = dVar;
        } else {
            intRange = intRange2;
        }
        C0699p0 c0699p0 = this.i;
        Z0.m(qVarW, this.a, (Function1) objI2, this.g, this.h, intRange, c0699p0, c0814p, 6);
        Z1.g(null, DefinitionKt.NO_Float_VALUE, c0699p0.x, c0814p, 0, 3);
        c0814p.p(true);
        return Unit.a;
    }
}
