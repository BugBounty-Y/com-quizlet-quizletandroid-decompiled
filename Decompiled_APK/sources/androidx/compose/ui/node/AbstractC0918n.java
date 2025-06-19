package androidx.compose.ui.node;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0918n extends androidx.compose.ui.p {
    public final int n = b0.f(this);
    public androidx.compose.ui.p o;

    @Override // androidx.compose.ui.p
    public final void C0() {
        super.C0();
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.L0(this.h);
            if (!pVar.m) {
                pVar.C0();
            }
        }
    }

    @Override // androidx.compose.ui.p
    public final void D0() {
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.D0();
        }
        super.D0();
    }

    @Override // androidx.compose.ui.p
    public final void H0() {
        super.H0();
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.H0();
        }
    }

    @Override // androidx.compose.ui.p
    public final void I0() {
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.I0();
        }
        super.I0();
    }

    @Override // androidx.compose.ui.p
    public final void J0() {
        super.J0();
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.J0();
        }
    }

    @Override // androidx.compose.ui.p
    public final void K0(androidx.compose.ui.p pVar) {
        this.a = pVar;
        for (androidx.compose.ui.p pVar2 = this.o; pVar2 != null; pVar2 = pVar2.f) {
            pVar2.K0(pVar);
        }
    }

    @Override // androidx.compose.ui.p
    public final void L0(a0 a0Var) {
        this.h = a0Var;
        for (androidx.compose.ui.p pVar = this.o; pVar != null; pVar = pVar.f) {
            pVar.L0(a0Var);
        }
    }

    public final void M0(InterfaceC0917m interfaceC0917m) {
        androidx.compose.ui.p pVar = ((androidx.compose.ui.p) interfaceC0917m).a;
        if (pVar != interfaceC0917m) {
            androidx.compose.ui.p pVar2 = interfaceC0917m instanceof androidx.compose.ui.p ? (androidx.compose.ui.p) interfaceC0917m : null;
            androidx.compose.ui.p pVar3 = pVar2 != null ? pVar2.e : null;
            if (pVar != this.a || !Intrinsics.b(pVar3, this)) {
                throw new IllegalStateException("Cannot delegate to an already delegated node");
            }
            return;
        }
        if (pVar.m) {
            W4.f("Cannot delegate to an already attached node");
            throw null;
        }
        pVar.K0(this.a);
        int i = this.c;
        int iG = b0.g(pVar);
        pVar.c = iG;
        int i2 = this.c;
        int i3 = iG & 2;
        if (i3 != 0 && (i2 & 2) != 0 && !(this instanceof InterfaceC0926w)) {
            W4.f("Delegating to multiple LayoutModifierNodes without the delegating node implementing LayoutModifierNode itself is not allowed.\nDelegating Node: " + this + "\nDelegate Node: " + pVar);
            throw null;
        }
        pVar.f = this.o;
        this.o = pVar;
        pVar.e = this;
        O0(iG | i2, false);
        if (this.m) {
            if (i3 == 0 || (i & 2) != 0) {
                L0(this.h);
            } else {
                V v = AbstractC0910f.v(this).w;
                this.a.L0(null);
                v.k();
            }
            pVar.C0();
            pVar.I0();
            b0.a(pVar);
        }
    }

    public final void N0(InterfaceC0917m interfaceC0917m) {
        androidx.compose.ui.p pVar = null;
        for (androidx.compose.ui.p pVar2 = this.o; pVar2 != null; pVar2 = pVar2.f) {
            if (pVar2 == interfaceC0917m) {
                boolean z = pVar2.m;
                if (z) {
                    androidx.collection.C c = b0.a;
                    if (!z) {
                        W4.f("autoInvalidateRemovedNode called on unattached node");
                        throw null;
                    }
                    b0.b(pVar2, -1, 2);
                    pVar2.J0();
                    pVar2.D0();
                }
                pVar2.K0(pVar2);
                pVar2.d = 0;
                if (pVar == null) {
                    this.o = pVar2.f;
                } else {
                    pVar.f = pVar2.f;
                }
                pVar2.f = null;
                pVar2.e = null;
                int i = this.c;
                int iG = b0.g(this);
                O0(iG, true);
                if (this.m && (i & 2) != 0 && (iG & 2) == 0) {
                    V v = AbstractC0910f.v(this).w;
                    this.a.L0(null);
                    v.k();
                    return;
                }
                return;
            }
            pVar = pVar2;
        }
        throw new IllegalStateException(("Could not find delegate: " + interfaceC0917m).toString());
    }

    public final void O0(int i, boolean z) {
        androidx.compose.ui.p pVar;
        int i2 = this.c;
        this.c = i;
        if (i2 != i) {
            androidx.compose.ui.p pVar2 = this.a;
            if (pVar2 == this) {
                this.d = i;
            }
            if (this.m) {
                androidx.compose.ui.p pVar3 = this;
                while (pVar3 != null) {
                    i |= pVar3.c;
                    pVar3.c = i;
                    if (pVar3 == pVar2) {
                        break;
                    } else {
                        pVar3 = pVar3.e;
                    }
                }
                if (z && pVar3 == pVar2) {
                    i = b0.g(pVar2);
                    pVar2.c = i;
                }
                int i3 = i | ((pVar3 == null || (pVar = pVar3.f) == null) ? 0 : pVar.d);
                while (pVar3 != null) {
                    i3 |= pVar3.c;
                    pVar3.d = i3;
                    pVar3 = pVar3.e;
                }
            }
        }
    }
}
