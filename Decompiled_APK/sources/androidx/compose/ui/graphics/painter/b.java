package androidx.compose.ui.graphics.painter;

import androidx.appcompat.app.L;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.geometry.c;
import androidx.compose.ui.geometry.e;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.drawscope.d;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class b {
    public k a;
    public boolean b;
    public AbstractC0874w c;
    public float d = 1.0f;
    public androidx.compose.ui.unit.k e = androidx.compose.ui.unit.k.a;

    public b() {
        new C0775b0(this, 13);
    }

    public boolean c(float f) {
        return false;
    }

    public boolean e(AbstractC0874w abstractC0874w) {
        return false;
    }

    public void f(androidx.compose.ui.unit.k kVar) {
    }

    public final void g(d dVar, long j, float f, AbstractC0874w abstractC0874w) {
        if (this.d != f) {
            if (!c(f)) {
                if (f == 1.0f) {
                    k kVar = this.a;
                    if (kVar != null) {
                        kVar.d(f);
                    }
                    this.b = false;
                } else {
                    k kVarG = this.a;
                    if (kVarG == null) {
                        kVarG = F.g();
                        this.a = kVarG;
                    }
                    kVarG.d(f);
                    this.b = true;
                }
            }
            this.d = f;
        }
        if (!Intrinsics.b(this.c, abstractC0874w)) {
            if (!e(abstractC0874w)) {
                if (abstractC0874w == null) {
                    k kVar2 = this.a;
                    if (kVar2 != null) {
                        kVar2.g(null);
                    }
                    this.b = false;
                } else {
                    k kVarG2 = this.a;
                    if (kVarG2 == null) {
                        kVarG2 = F.g();
                        this.a = kVarG2;
                    }
                    kVarG2.g(abstractC0874w);
                    this.b = true;
                }
            }
            this.c = abstractC0874w;
        }
        androidx.compose.ui.unit.k layoutDirection = dVar.getLayoutDirection();
        if (this.e != layoutDirection) {
            f(layoutDirection);
            this.e = layoutDirection;
        }
        float fD = e.d(dVar.g()) - e.d(j);
        float fB = e.b(dVar.g()) - e.b(j);
        ((L) dVar.e0().b).M(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, fD, fB);
        if (f > DefinitionKt.NO_Float_VALUE) {
            try {
                if (e.d(j) > DefinitionKt.NO_Float_VALUE && e.b(j) > DefinitionKt.NO_Float_VALUE) {
                    if (this.b) {
                        c cVarA = R4.a(0L, T4.a(e.d(j), e.b(j)));
                        InterfaceC0858s interfaceC0858sO = dVar.e0().o();
                        k kVarG3 = this.a;
                        if (kVarG3 == null) {
                            kVarG3 = F.g();
                            this.a = kVarG3;
                        }
                        try {
                            interfaceC0858sO.g(cVarA, kVarG3);
                            i(dVar);
                            interfaceC0858sO.q();
                        } catch (Throwable th) {
                            interfaceC0858sO.q();
                            throw th;
                        }
                    } else {
                        i(dVar);
                    }
                }
            } catch (Throwable th2) {
                ((L) dVar.e0().b).M(-0.0f, -0.0f, -fD, -fB);
                throw th2;
            }
        }
        ((L) dVar.e0().b).M(-0.0f, -0.0f, -fD, -fB);
    }

    public abstract long h();

    public abstract void i(d dVar);
}
