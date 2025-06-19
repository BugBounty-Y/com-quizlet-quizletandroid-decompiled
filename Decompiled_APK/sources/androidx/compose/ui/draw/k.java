package androidx.compose.ui.draw;

import androidx.collection.G;
import androidx.collection.P;
import androidx.compose.ui.graphics.E;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.collections.C4930v;

/* loaded from: classes.dex */
public final class k implements E {
    public G a;
    public E b;

    @Override // androidx.compose.ui.graphics.E
    public final void a(androidx.compose.ui.graphics.layer.b bVar) {
        E e = this.b;
        if (e != null) {
            e.a(bVar);
        }
    }

    @Override // androidx.compose.ui.graphics.E
    public final androidx.compose.ui.graphics.layer.b b() {
        E e = this.b;
        if (e == null) {
            W4.f("GraphicsContext not provided");
            throw null;
        }
        androidx.compose.ui.graphics.layer.b bVarB = e.b();
        G g = this.a;
        if (g != null) {
            g.a(bVarB);
            return bVarB;
        }
        Object[] objArr = P.a;
        G g2 = new G(1);
        g2.a(bVarB);
        this.a = g2;
        return bVarB;
    }

    public final void c() {
        G g = this.a;
        if (g != null) {
            Object[] objArr = g.a;
            int i = g.b;
            for (int i2 = 0; i2 < i; i2++) {
                a((androidx.compose.ui.graphics.layer.b) objArr[i2]);
            }
            C4930v.o(g.a, null, 0, g.b);
            g.b = 0;
        }
    }
}
