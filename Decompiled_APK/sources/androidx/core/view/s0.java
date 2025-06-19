package androidx.core.view;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3283v6;

/* loaded from: classes.dex */
public abstract class s0 {
    public final D0 a;
    public androidx.core.graphics.e[] b;

    public s0() {
        this(new D0((D0) null));
    }

    public final void a() {
        androidx.core.graphics.e[] eVarArr = this.b;
        if (eVarArr != null) {
            androidx.core.graphics.e eVarG = eVarArr[0];
            androidx.core.graphics.e eVarG2 = eVarArr[1];
            D0 d0 = this.a;
            if (eVarG2 == null) {
                eVarG2 = d0.a.g(2);
            }
            if (eVarG == null) {
                eVarG = d0.a.g(1);
            }
            g(androidx.core.graphics.e.a(eVarG, eVarG2));
            androidx.core.graphics.e eVar = this.b[AbstractC3283v6.a(16)];
            if (eVar != null) {
                f(eVar);
            }
            androidx.core.graphics.e eVar2 = this.b[AbstractC3283v6.a(32)];
            if (eVar2 != null) {
                d(eVar2);
            }
            androidx.core.graphics.e eVar3 = this.b[AbstractC3283v6.a(64)];
            if (eVar3 != null) {
                h(eVar3);
            }
        }
    }

    public abstract D0 b();

    public void c(int i, androidx.core.graphics.e eVar) {
        if (this.b == null) {
            this.b = new androidx.core.graphics.e[10];
        }
        for (int i2 = 1; i2 <= 512; i2 <<= 1) {
            if ((i & i2) != 0) {
                this.b[AbstractC3283v6.a(i2)] = eVar;
            }
        }
    }

    public void d(androidx.core.graphics.e eVar) {
    }

    public abstract void e(androidx.core.graphics.e eVar);

    public void f(androidx.core.graphics.e eVar) {
    }

    public abstract void g(androidx.core.graphics.e eVar);

    public void h(androidx.core.graphics.e eVar) {
    }

    public s0(D0 d0) {
        this.a = d0;
    }
}
