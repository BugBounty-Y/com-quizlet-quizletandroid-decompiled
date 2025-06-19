package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.AbstractC0874w;

/* loaded from: classes.dex */
public final class K extends androidx.compose.ui.graphics.painter.b {
    public final InterfaceC0773a0 f = C0776c.z(new androidx.compose.ui.geometry.e(0));
    public final InterfaceC0773a0 g = C0776c.z(Boolean.FALSE);
    public final F h;
    public final H0 i;
    public float j;
    public AbstractC0874w k;
    public int l;

    public K(C0864c c0864c) {
        F f = new F(c0864c);
        f.f = new androidx.compose.animation.core.K(this, 29);
        this.h = f;
        this.i = C0776c.w(0);
        this.j = 1.0f;
        this.l = -1;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean c(float f) {
        this.j = f;
        return true;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean e(AbstractC0874w abstractC0874w) {
        this.k = abstractC0874w;
        return true;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final long h() {
        return ((androidx.compose.ui.geometry.e) ((L0) this.f).getValue()).a;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void i(androidx.compose.ui.graphics.drawscope.d dVar) {
        AbstractC0874w abstractC0874w = this.k;
        F f = this.h;
        if (abstractC0874w == null) {
            abstractC0874w = (AbstractC0874w) ((L0) f.g).getValue();
        }
        if (((Boolean) ((L0) this.g).getValue()).booleanValue() && dVar.getLayoutDirection() == androidx.compose.ui.unit.k.b) {
            long jO0 = dVar.o0();
            com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
            long jR = cVarE0.r();
            cVarE0.o().e();
            try {
                ((androidx.appcompat.app.L) cVarE0.b).Q(-1.0f, 1.0f, jO0);
                f.e(dVar, this.j, abstractC0874w);
            } finally {
                d0.y(cVarE0, jR);
            }
        } else {
            f.e(dVar, this.j, abstractC0874w);
        }
        this.l = this.i.i();
    }
}
