package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class a extends androidx.constraintlayout.core.state.g {
    public final /* synthetic */ int n0;
    public float o0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(k kVar, int i, int i2) {
        super(kVar, i);
        this.n0 = i2;
    }

    @Override // androidx.constraintlayout.core.state.g, androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final void apply() {
        switch (this.n0) {
            case 0:
                Iterator it2 = this.m0.iterator();
                while (it2.hasNext()) {
                    androidx.constraintlayout.core.state.b bVarB = this.k0.b(it2.next());
                    bVarB.g();
                    Object obj = this.N;
                    if (obj != null) {
                        bVarB.o(obj);
                    } else {
                        Object obj2 = this.O;
                        if (obj2 != null) {
                            bVarB.j0 = 6;
                            bVarB.O = obj2;
                        } else {
                            bVarB.o(0);
                        }
                    }
                    Object obj3 = this.P;
                    if (obj3 != null) {
                        bVarB.j0 = 7;
                        bVarB.P = obj3;
                    } else {
                        Object obj4 = this.Q;
                        if (obj4 != null) {
                            bVarB.i(obj4);
                        } else {
                            bVarB.i(0);
                        }
                    }
                    float f = this.o0;
                    if (f != 0.5f) {
                        bVarB.h = f;
                    }
                }
                break;
            default:
                Iterator it3 = this.m0.iterator();
                while (it3.hasNext()) {
                    androidx.constraintlayout.core.state.b bVarB2 = this.k0.b(it3.next());
                    bVarB2.h();
                    Object obj5 = this.R;
                    if (obj5 != null) {
                        bVarB2.p(obj5);
                    } else {
                        Object obj6 = this.S;
                        if (obj6 != null) {
                            bVarB2.j0 = 10;
                            bVarB2.S = obj6;
                        } else {
                            bVarB2.p(0);
                        }
                    }
                    Object obj7 = this.U;
                    if (obj7 != null) {
                        bVarB2.j0 = 12;
                        bVarB2.U = obj7;
                    } else {
                        Object obj8 = this.V;
                        if (obj8 != null) {
                            bVarB2.e(obj8);
                        } else {
                            bVarB2.e(0);
                        }
                    }
                    float f2 = this.o0;
                    if (f2 != 0.5f) {
                        bVarB2.i = f2;
                    }
                }
                break;
        }
    }
}
