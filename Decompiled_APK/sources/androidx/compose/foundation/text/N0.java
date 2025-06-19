package androidx.compose.foundation.text;

import androidx.camera.camera2.internal.C0143u;
import androidx.compose.animation.C0278e;
import androidx.compose.animation.C0281h;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0473q;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.C0935c0;
import androidx.compose.ui.text.AbstractC1013n;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.ContentType;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N0 {
    public final C0995g a;
    public final InterfaceC0773a0 b = C0776c.z(null);
    public C0995g c;
    public final androidx.compose.runtime.snapshots.q d;

    public N0(C0995g c0995g) {
        androidx.compose.ui.text.D d;
        this.a = c0995g;
        C0984d c0984d = new C0984d(c0995g);
        List listA = c0995g.a(c0995g.a.length());
        int size = listA.size();
        for (int i = 0; i < size; i++) {
            C0985e c0985e = (C0985e) listA.get(i);
            androidx.compose.ui.text.I iB = ((AbstractC1013n) c0985e.a).b();
            if (iB != null && (d = iB.a) != null) {
                c0984d.c(d, c0985e.b, c0985e.c);
            }
        }
        this.c = c0984d.j();
        this.d = new androidx.compose.runtime.snapshots.q();
    }

    public static C0985e c(C0985e c0985e, androidx.compose.ui.text.H h) {
        int iE = h.e(h.b.f - 1, false);
        int i = c0985e.b;
        if (i < iE) {
            return new C0985e(i, Math.min(c0985e.c, iE), c0985e.a, c0985e.d);
        }
        return null;
    }

    public final void a(InterfaceC0806l interfaceC0806l, int i) {
        char c;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1154651354);
        char c2 = 2;
        int i2 = (c0814p.h(this) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = (C0935c0) c0814p.j(AbstractC0955m0.p);
            C0995g c0995g = this.c;
            List listA = c0995g.a(c0995g.a.length());
            int size = listA.size();
            int i3 = 0;
            while (i3 < size) {
                C0985e c0985e = (C0985e) listA.get(i3);
                if (c0985e.b != c0985e.c) {
                    c0814p.X(1385536272);
                    Object objI = c0814p.I();
                    Object obj2 = C0804k.a;
                    if (objI == obj2) {
                        objI = androidx.compose.animation.d0.i(c0814p);
                    }
                    androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
                    c = c2;
                    androidx.compose.ui.q qVarP = AbstractC0460p.p(androidx.compose.ui.graphics.F.p(androidx.compose.ui.n.b, new C0278e(24, this, c0985e)).g(new P0(new C0143u(12, this, c0985e))), lVar);
                    androidx.compose.ui.input.pointer.j.a.getClass();
                    androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(androidx.compose.ui.input.pointer.l.f(qVarP, androidx.compose.ui.input.pointer.l.b), false, C0491h.p);
                    boolean zH = c0814p.h(this) | c0814p.f(c0985e) | c0814p.h(obj);
                    Object objI2 = c0814p.I();
                    if (zH || objI2 == obj2) {
                        objI2 = new C0473q(this, c0985e, obj, 5);
                        c0814p.i0(objI2);
                    }
                    AbstractC0409s.a(AbstractC0460p.m(qVarA, lVar, null, true, null, (Function0) objI2), c0814p, 0);
                    AbstractC1013n abstractC1013n = (AbstractC1013n) c0985e.a;
                    androidx.compose.ui.text.I iB = abstractC1013n.b();
                    if (iB == null || (iB.a == null && iB.b == null && iB.c == null && iB.d == null)) {
                        c0814p.X(1388165134);
                        c0814p.p(false);
                    } else {
                        c0814p.X(1386296950);
                        Object objI3 = c0814p.I();
                        if (objI3 == obj2) {
                            objI3 = new C0502j0();
                            c0814p.i0(objI3);
                        }
                        C0502j0 c0502j0 = (C0502j0) objI3;
                        Object objI4 = c0814p.I();
                        if (objI4 == obj2) {
                            objI4 = new L0(c0502j0, lVar, null);
                            c0814p.i0(objI4);
                        }
                        C0776c.f(c0814p, lVar, (Function2) objI4);
                        Boolean boolValueOf = Boolean.valueOf((c0502j0.a.i() & 2) != 0);
                        androidx.compose.runtime.H0 h0 = c0502j0.a;
                        Boolean boolValueOf2 = Boolean.valueOf((h0.i() & 1) != 0);
                        Boolean boolValueOf3 = Boolean.valueOf((h0.i() & 4) != 0);
                        androidx.compose.ui.text.I iB2 = abstractC1013n.b();
                        androidx.compose.ui.text.D d = iB2 != null ? iB2.a : null;
                        androidx.compose.ui.text.I iB3 = abstractC1013n.b();
                        androidx.compose.ui.text.D d2 = iB3 != null ? iB3.b : null;
                        androidx.compose.ui.text.I iB4 = abstractC1013n.b();
                        androidx.compose.ui.text.D d3 = iB4 != null ? iB4.c : null;
                        androidx.compose.ui.text.I iB5 = abstractC1013n.b();
                        Object[] objArr = {boolValueOf, boolValueOf2, boolValueOf3, d, d2, d3, iB5 != null ? iB5.d : null};
                        boolean zH2 = c0814p.h(this) | c0814p.f(c0985e);
                        Object objI5 = c0814p.I();
                        if (zH2 || objI5 == obj2) {
                            objI5 = new androidx.activity.compose.g(this, c0985e, c0502j0, 13);
                            c0814p.i0(objI5);
                        }
                        b(objArr, (Function1) objI5, c0814p, (i2 << 6) & 896);
                        c0814p.p(false);
                    }
                    c0814p.p(false);
                } else {
                    c = c2;
                    c0814p.X(1388179022);
                    c0814p.p(false);
                }
                i3++;
                c2 = c;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0281h(this, i, 11);
        }
    }

    public final void b(Object[] objArr, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2083052099);
        int i2 = (i & 48) == 0 ? (c0814p.h(function1) ? 32 : 16) | i : i;
        if ((i & 384) == 0) {
            i2 |= c0814p.h(this) ? 256 : 128;
        }
        c0814p.U(-416630839, Integer.valueOf(objArr.length));
        for (Object obj : objArr) {
            i2 |= c0814p.h(obj) ? 4 : 0;
        }
        c0814p.p(false);
        if ((i2 & 14) == 0) {
            i2 |= 2;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.animation.core.O0 o0 = new androidx.compose.animation.core.O0();
            ArrayList arrayList = o0.a;
            arrayList.add(function1);
            o0.a(objArr);
            Object[] array = arrayList.toArray(new Object[arrayList.size()]);
            boolean zH = c0814p.h(this) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new C0511o(this, function1, 1);
                c0814p.i0(objI);
            }
            C0776c.e(array, (Function1) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(i, 3, this, objArr, function1);
        }
    }
}
