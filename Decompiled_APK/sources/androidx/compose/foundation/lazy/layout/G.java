package androidx.compose.foundation.lazy.layout;

import androidx.compose.ui.node.InterfaceC0919o;
import com.google.android.gms.internal.mlkit_vision_barcode.U4;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G extends androidx.compose.ui.p implements InterfaceC0919o {
    public K n;

    @Override // androidx.compose.ui.p
    public final void E0() {
        this.n.j = this;
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.n.f();
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(androidx.compose.ui.node.G g) {
        ArrayList arrayList = this.n.i;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            E e = (E) arrayList.get(i);
            androidx.compose.ui.graphics.layer.b bVar = e.n;
            if (bVar != null) {
                long j = e.m;
                long j2 = bVar.s;
                float f = ((int) (j >> 32)) - ((int) (j2 >> 32));
                float f2 = ((int) (j & 4294967295L)) - ((int) (4294967295L & j2));
                androidx.compose.ui.graphics.drawscope.b bVar2 = g.a;
                ((androidx.appcompat.app.L) bVar2.b.b).S(f, f2);
                try {
                    U4.a(g, bVar);
                } finally {
                    ((androidx.appcompat.app.L) bVar2.b.b).S(-f, -f2);
                }
            }
        }
        g.b();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof G) && Intrinsics.b(this.n, ((G) obj).n);
    }

    public final int hashCode() {
        return this.n.hashCode();
    }

    public final String toString() {
        return "DisplayingDisappearingItemsNode(animator=" + this.n + ')';
    }
}
