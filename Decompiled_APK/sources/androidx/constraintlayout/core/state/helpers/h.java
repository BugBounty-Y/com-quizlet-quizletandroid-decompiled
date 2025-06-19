package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class h extends c {
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
                kVar.b(it2.next()).g();
            }
        }
        Iterator it3 = arrayList.iterator();
        androidx.constraintlayout.core.state.b bVar = null;
        androidx.constraintlayout.core.state.b bVar2 = null;
        while (it3.hasNext()) {
            Object next = it3.next();
            androidx.constraintlayout.core.state.b bVarB = kVar.b(next);
            if (bVar2 == null) {
                Object obj = this.N;
                if (obj != null) {
                    bVarB.o(obj);
                    bVarB.k(this.l).m(this.r);
                } else {
                    Object obj2 = this.O;
                    if (obj2 != null) {
                        bVarB.j0 = 6;
                        bVarB.O = obj2;
                        bVarB.k(this.l).m(this.r);
                    } else {
                        Object obj3 = this.J;
                        if (obj3 != null) {
                            bVarB.o(obj3);
                            bVarB.k(this.j).m(this.p);
                        } else {
                            Object obj4 = this.K;
                            if (obj4 != null) {
                                bVarB.j0 = 6;
                                bVarB.O = obj4;
                                bVarB.k(this.j).m(this.p);
                            } else {
                                String string = bVarB.a.toString();
                                bVarB.o(0);
                                bVarB.l(Float.valueOf(w(string))).n(Float.valueOf(v(string)));
                            }
                        }
                    }
                }
                bVar2 = bVarB;
            }
            if (bVar != null) {
                String string2 = bVar.a.toString();
                String string3 = bVarB.a.toString();
                Object obj5 = bVarB.a;
                bVar.j0 = 7;
                bVar.P = obj5;
                bVar.l(Float.valueOf(u(string2))).n(Float.valueOf(t(string2)));
                Object obj6 = bVar.a;
                bVarB.j0 = 6;
                bVarB.O = obj6;
                bVarB.l(Float.valueOf(w(string3))).n(Float.valueOf(v(string3)));
            }
            String string4 = next.toString();
            HashMap map = this.o0;
            float fFloatValue = map.containsKey(string4) ? ((Float) map.get(string4)).floatValue() : -1.0f;
            if (fFloatValue != -1.0f) {
                bVarB.f = fFloatValue;
            }
            bVar = bVarB;
        }
        if (bVar != null) {
            Object obj7 = this.P;
            if (obj7 != null) {
                bVar.j0 = 7;
                bVar.P = obj7;
                bVar.k(this.m).m(this.s);
            } else {
                Object obj8 = this.Q;
                if (obj8 != null) {
                    bVar.i(obj8);
                    bVar.k(this.m).m(this.s);
                } else {
                    Object obj9 = this.L;
                    if (obj9 != null) {
                        bVar.j0 = 7;
                        bVar.P = obj9;
                        bVar.k(this.k).m(this.q);
                    } else {
                        Object obj10 = this.M;
                        if (obj10 != null) {
                            bVar.i(obj10);
                            bVar.k(this.k).m(this.q);
                        } else {
                            String string5 = bVar.a.toString();
                            bVar.i(0);
                            bVar.l(Float.valueOf(u(string5))).n(Float.valueOf(t(string5)));
                        }
                    }
                }
            }
        }
        if (bVar2 == null) {
            return;
        }
        float f = this.n0;
        if (f != 0.5f) {
            bVar2.h = f;
        }
        int iOrdinal = this.t0.ordinal();
        if (iOrdinal == 0) {
            bVar2.d = 0;
        } else if (iOrdinal == 1) {
            bVar2.d = 1;
        } else {
            if (iOrdinal != 2) {
                return;
            }
            bVar2.d = 2;
        }
    }
}
