package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class i extends c {
    @Override // androidx.constraintlayout.core.state.g, androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final void apply() {
        k kVar;
        ArrayList arrayList = this.m0;
        Iterator it2 = arrayList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            kVar = this.k0;
            if (!zHasNext) {
                break;
            } else {
                kVar.b(it2.next()).h();
            }
        }
        Iterator it3 = arrayList.iterator();
        androidx.constraintlayout.core.state.b bVar = null;
        androidx.constraintlayout.core.state.b bVar2 = null;
        while (it3.hasNext()) {
            Object next = it3.next();
            androidx.constraintlayout.core.state.b bVarB = kVar.b(next);
            if (bVar2 == null) {
                Object obj = this.R;
                if (obj != null) {
                    bVarB.p(obj);
                    bVarB.k(this.n).m(this.t);
                } else {
                    Object obj2 = this.S;
                    if (obj2 != null) {
                        bVarB.j0 = 10;
                        bVarB.S = obj2;
                        bVarB.k(this.n).m(this.t);
                    } else {
                        String string = bVarB.a.toString();
                        bVarB.p(0);
                        bVarB.l(Float.valueOf(w(string))).n(Float.valueOf(v(string)));
                    }
                }
                bVar2 = bVarB;
            }
            if (bVar != null) {
                String string2 = bVar.a.toString();
                String string3 = bVarB.a.toString();
                Object obj3 = bVarB.a;
                bVar.j0 = 12;
                bVar.U = obj3;
                bVar.l(Float.valueOf(u(string2))).n(Float.valueOf(t(string2)));
                Object obj4 = bVar.a;
                bVarB.j0 = 10;
                bVarB.S = obj4;
                bVarB.l(Float.valueOf(w(string3))).n(Float.valueOf(v(string3)));
            }
            String string4 = next.toString();
            HashMap map = this.o0;
            float fFloatValue = map.containsKey(string4) ? ((Float) map.get(string4)).floatValue() : -1.0f;
            if (fFloatValue != -1.0f) {
                bVarB.g = fFloatValue;
            }
            bVar = bVarB;
        }
        if (bVar != null) {
            Object obj5 = this.U;
            if (obj5 != null) {
                bVar.j0 = 12;
                bVar.U = obj5;
                bVar.k(this.o).m(this.u);
            } else {
                Object obj6 = this.V;
                if (obj6 != null) {
                    bVar.e(obj6);
                    bVar.k(this.o).m(this.u);
                } else {
                    String string5 = bVar.a.toString();
                    bVar.e(0);
                    bVar.l(Float.valueOf(u(string5))).n(Float.valueOf(t(string5)));
                }
            }
        }
        if (bVar2 == null) {
            return;
        }
        float f = this.n0;
        if (f != 0.5f) {
            bVar2.i = f;
        }
        int iOrdinal = this.t0.ordinal();
        if (iOrdinal == 0) {
            bVar2.e = 0;
        } else if (iOrdinal == 1) {
            bVar2.e = 1;
        } else {
            if (iOrdinal != 2) {
                return;
            }
            bVar2.e = 2;
        }
    }
}
