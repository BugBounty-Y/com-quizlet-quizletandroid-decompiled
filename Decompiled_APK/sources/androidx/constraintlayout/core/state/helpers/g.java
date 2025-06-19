package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class g implements d, androidx.constraintlayout.core.state.h {
    public final k a;
    public int b;
    public androidx.constraintlayout.core.widgets.i c;
    public int d = -1;
    public int e = -1;
    public float f = DefinitionKt.NO_Float_VALUE;
    public String g;

    public g(k kVar) {
        this.a = kVar;
    }

    @Override // androidx.constraintlayout.core.state.h
    public final void a(androidx.constraintlayout.core.widgets.e eVar) {
        if (eVar instanceof androidx.constraintlayout.core.widgets.i) {
            this.c = (androidx.constraintlayout.core.widgets.i) eVar;
        } else {
            this.c = null;
        }
    }

    @Override // androidx.constraintlayout.core.state.helpers.d, androidx.constraintlayout.core.state.h
    public final void apply() {
        this.c.W(this.b);
        int i = this.d;
        if (i != -1) {
            androidx.constraintlayout.core.widgets.i iVar = this.c;
            if (i <= -1) {
                iVar.getClass();
                return;
            }
            iVar.t0 = -1.0f;
            iVar.u0 = i;
            iVar.v0 = -1;
            return;
        }
        int i2 = this.e;
        if (i2 != -1) {
            androidx.constraintlayout.core.widgets.i iVar2 = this.c;
            if (i2 <= -1) {
                iVar2.getClass();
                return;
            }
            iVar2.t0 = -1.0f;
            iVar2.u0 = -1;
            iVar2.v0 = i2;
            return;
        }
        androidx.constraintlayout.core.widgets.i iVar3 = this.c;
        float f = this.f;
        if (f <= -1.0f) {
            iVar3.getClass();
            return;
        }
        iVar3.t0 = f;
        iVar3.u0 = -1;
        iVar3.v0 = -1;
    }

    @Override // androidx.constraintlayout.core.state.h
    public final androidx.constraintlayout.core.widgets.e b() {
        if (this.c == null) {
            this.c = new androidx.constraintlayout.core.widgets.i();
        }
        return this.c;
    }

    @Override // androidx.constraintlayout.core.state.h
    public final d c() {
        return null;
    }

    @Override // androidx.constraintlayout.core.state.h
    public final Object getKey() {
        return this.g;
    }
}
