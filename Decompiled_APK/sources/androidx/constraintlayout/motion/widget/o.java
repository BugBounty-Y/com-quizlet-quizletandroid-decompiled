package androidx.constraintlayout.motion.widget;

import android.util.SparseArray;
import androidx.compose.foundation.lazy.layout.n0;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class o {
    public float a = Float.NaN;
    public float b = Float.NaN;
    public int c = -1;
    public int d = -1;
    public final /* synthetic */ r e;

    public o(r rVar) {
        this.e = rVar;
    }

    public final void a() {
        int i = this.c;
        r rVar = this.e;
        if (i != -1 || this.d != -1) {
            if (i == -1) {
                int i2 = this.d;
                if (rVar.isAttachedToWindow()) {
                    int i3 = rVar.u;
                    if (i3 != i2) {
                        if (rVar.t == i2) {
                            rVar.q(DefinitionKt.NO_Float_VALUE);
                        } else if (rVar.v == i2) {
                            rVar.q(1.0f);
                        } else {
                            rVar.v = i2;
                            if (i3 == -1) {
                                rVar.L = false;
                                rVar.F = 1.0f;
                                rVar.C = DefinitionKt.NO_Float_VALUE;
                                rVar.D = DefinitionKt.NO_Float_VALUE;
                                rVar.E = rVar.getNanoTime();
                                rVar.A = rVar.getNanoTime();
                                rVar.G = false;
                                rVar.q = null;
                                throw null;
                            }
                            rVar.w(i3, i2);
                            rVar.q(1.0f);
                            rVar.D = DefinitionKt.NO_Float_VALUE;
                            rVar.q(1.0f);
                        }
                    }
                } else {
                    if (rVar.z1 == null) {
                        rVar.z1 = new o(rVar);
                    }
                    rVar.z1.d = i2;
                }
            } else {
                int i4 = this.d;
                if (i4 == -1) {
                    rVar.setState(q.b);
                    rVar.u = i;
                    rVar.t = -1;
                    rVar.v = -1;
                    n0 n0Var = rVar.k;
                    if (n0Var != null) {
                        float f = -1;
                        int i5 = n0Var.a;
                        SparseArray sparseArray = (SparseArray) n0Var.d;
                        int i6 = 0;
                        ConstraintLayout constraintLayout = (ConstraintLayout) n0Var.c;
                        if (i5 == i) {
                            androidx.constraintlayout.widget.g gVar = i == -1 ? (androidx.constraintlayout.widget.g) sparseArray.valueAt(0) : (androidx.constraintlayout.widget.g) sparseArray.get(i5);
                            int i7 = n0Var.b;
                            if (i7 == -1 || !((androidx.constraintlayout.widget.h) gVar.b.get(i7)).a(f, f)) {
                                while (true) {
                                    ArrayList arrayList = gVar.b;
                                    if (i6 >= arrayList.size()) {
                                        i6 = -1;
                                        break;
                                    } else if (((androidx.constraintlayout.widget.h) arrayList.get(i6)).a(f, f)) {
                                        break;
                                    } else {
                                        i6++;
                                    }
                                }
                                if (n0Var.b != i6) {
                                    ArrayList arrayList2 = gVar.b;
                                    androidx.constraintlayout.widget.o oVar = i6 != -1 ? ((androidx.constraintlayout.widget.h) arrayList2.get(i6)).f : null;
                                    if (i6 != -1) {
                                        int i8 = ((androidx.constraintlayout.widget.h) arrayList2.get(i6)).e;
                                    }
                                    if (oVar != null) {
                                        n0Var.b = i6;
                                        oVar.a(constraintLayout);
                                    }
                                }
                            }
                        } else {
                            n0Var.a = i;
                            androidx.constraintlayout.widget.g gVar2 = (androidx.constraintlayout.widget.g) sparseArray.get(i);
                            while (true) {
                                ArrayList arrayList3 = gVar2.b;
                                if (i6 >= arrayList3.size()) {
                                    i6 = -1;
                                    break;
                                } else if (((androidx.constraintlayout.widget.h) arrayList3.get(i6)).a(f, f)) {
                                    break;
                                } else {
                                    i6++;
                                }
                            }
                            ArrayList arrayList4 = gVar2.b;
                            androidx.constraintlayout.widget.o oVar2 = i6 == -1 ? gVar2.d : ((androidx.constraintlayout.widget.h) arrayList4.get(i6)).f;
                            if (i6 != -1) {
                                int i9 = ((androidx.constraintlayout.widget.h) arrayList4.get(i6)).e;
                            }
                            if (oVar2 != null) {
                                n0Var.b = i6;
                                oVar2.a(constraintLayout);
                            }
                        }
                    }
                } else {
                    rVar.w(i, i4);
                }
            }
            rVar.setState(q.b);
        }
        if (Float.isNaN(this.b)) {
            if (Float.isNaN(this.a)) {
                return;
            }
            rVar.setProgress(this.a);
            return;
        }
        float f2 = this.a;
        float f3 = this.b;
        if (rVar.isAttachedToWindow()) {
            rVar.setProgress(f2);
            rVar.setState(q.c);
            rVar.s = f3;
            float f4 = DefinitionKt.NO_Float_VALUE;
            if (f3 != DefinitionKt.NO_Float_VALUE) {
                if (f3 > DefinitionKt.NO_Float_VALUE) {
                    f4 = 1.0f;
                }
                rVar.q(f4);
            } else if (f2 != DefinitionKt.NO_Float_VALUE && f2 != 1.0f) {
                if (f2 > 0.5f) {
                    f4 = 1.0f;
                }
                rVar.q(f4);
            }
        } else {
            if (rVar.z1 == null) {
                rVar.z1 = new o(rVar);
            }
            o oVar3 = rVar.z1;
            oVar3.a = f2;
            oVar3.b = f3;
        }
        this.a = Float.NaN;
        this.b = Float.NaN;
        this.c = -1;
        this.d = -1;
    }
}
