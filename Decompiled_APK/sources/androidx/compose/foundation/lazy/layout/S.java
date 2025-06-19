package androidx.compose.foundation.lazy.layout;

import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ c0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ Function2 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(c0 c0Var, androidx.compose.ui.q qVar, Function2 function2, InterfaceC0773a0 interfaceC0773a0) {
        super(3);
        this.a = c0Var;
        this.b = qVar;
        this.c = function2;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        androidx.compose.ui.q qVarG;
        androidx.compose.runtime.saveable.c cVar = (androidx.compose.runtime.saveable.c) obj;
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        Object objI = c0814p.I();
        Object obj4 = C0804k.a;
        if (objI == obj4) {
            objI = new M(cVar, new androidx.compose.foundation.lazy.j(this.d, 2));
            c0814p.i0(objI);
        }
        M m = (M) objI;
        Object objI2 = c0814p.I();
        if (objI2 == obj4) {
            objI2 = new androidx.compose.ui.layout.e0(new androidx.work.impl.model.l(m));
            c0814p.i0(objI2);
        }
        androidx.compose.ui.layout.e0 e0Var = (androidx.compose.ui.layout.e0) objI2;
        c0 c0Var = this.a;
        if (c0Var != null) {
            c0814p.X(205264983);
            c0814p.X(6622915);
            q0 q0Var = r0.a;
            if (q0Var != null) {
                c0814p.X(1213893039);
                c0814p.p(false);
            } else {
                c0814p.X(1213931944);
                View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
                boolean zF = c0814p.f(view);
                Object objI3 = c0814p.I();
                if (zF || objI3 == obj4) {
                    objI3 = new RunnableC0430b(view);
                    c0814p.i0(objI3);
                }
                q0Var = (RunnableC0430b) objI3;
                c0814p.p(false);
            }
            c0814p.p(false);
            Object[] objArr = {c0Var, m, e0Var, q0Var};
            boolean zF2 = c0814p.f(c0Var) | c0814p.h(m) | c0814p.h(e0Var) | c0814p.h(q0Var);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == obj4) {
                objI4 = new Q(c0Var, m, e0Var, q0Var);
                c0814p.i0(objI4);
            }
            C0776c.e(objArr, (Function1) objI4, c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(205858881);
            c0814p.p(false);
        }
        int i = d0.b;
        androidx.compose.ui.q qVar = this.b;
        if (c0Var != null && (qVarG = qVar.g(new TraversablePrefetchStateModifierElement(c0Var))) != null) {
            qVar = qVarG;
        }
        boolean zF3 = c0814p.f(m);
        Object obj5 = this.c;
        boolean zF4 = zF3 | c0814p.f(obj5);
        Object objI5 = c0814p.I();
        if (zF4 || objI5 == obj4) {
            objI5 = new androidx.compose.foundation.contextmenu.i(7, m, obj5);
            c0814p.i0(objI5);
        }
        AbstractC0897s.d(e0Var, qVar, (Function2) objI5, c0814p, 8);
        return Unit.a;
    }
}
