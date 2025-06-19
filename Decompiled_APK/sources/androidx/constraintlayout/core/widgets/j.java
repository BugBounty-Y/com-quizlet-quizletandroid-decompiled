package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.widgets.analyzer.o;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes.dex */
public abstract class j extends e {
    public e[] t0 = new e[4];
    public int u0 = 0;

    public final void V(e eVar) {
        if (eVar == this || eVar == null) {
            return;
        }
        int i = this.u0 + 1;
        e[] eVarArr = this.t0;
        if (i > eVarArr.length) {
            this.t0 = (e[]) Arrays.copyOf(eVarArr, eVarArr.length * 2);
        }
        e[] eVarArr2 = this.t0;
        int i2 = this.u0;
        eVarArr2[i2] = eVar;
        this.u0 = i2 + 1;
    }

    public final void W(int i, o oVar, ArrayList arrayList) {
        for (int i2 = 0; i2 < this.u0; i2++) {
            e eVar = this.t0[i2];
            ArrayList arrayList2 = oVar.a;
            if (!arrayList2.contains(eVar)) {
                arrayList2.add(eVar);
            }
        }
        for (int i3 = 0; i3 < this.u0; i3++) {
            androidx.constraintlayout.core.widgets.analyzer.i.b(this.t0[i3], i, arrayList, oVar);
        }
    }

    public void X() {
    }
}
