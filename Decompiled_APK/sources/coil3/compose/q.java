package coil3.compose;

import androidx.appcompat.app.L;
import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0845e;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;

/* loaded from: classes.dex */
public final class q extends androidx.compose.ui.graphics.painter.b {
    public final coil3.j f;

    public q(coil3.j jVar) {
        this.f = jVar;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final long h() {
        coil3.j jVar = this.f;
        int width = jVar.getWidth();
        float f = width > 0 ? width : Float.NaN;
        int iB = jVar.b();
        return T4.a(f, iB > 0 ? iB : Float.NaN);
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void i(androidx.compose.ui.graphics.drawscope.d dVar) {
        coil3.j jVar = this.f;
        int width = jVar.getWidth();
        float fD = width > 0 ? androidx.compose.ui.geometry.e.d(dVar.g()) / width : 1.0f;
        int iB = jVar.b();
        float fB = iB > 0 ? androidx.compose.ui.geometry.e.b(dVar.g()) / iB : 1.0f;
        com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
        long jR = cVarE0.r();
        cVarE0.o().e();
        try {
            ((L) cVarE0.b).Q(fD, fB, 0L);
            jVar.d(AbstractC0845e.a(dVar.e0().o()));
        } finally {
            d0.y(cVarE0, jR);
        }
    }
}
