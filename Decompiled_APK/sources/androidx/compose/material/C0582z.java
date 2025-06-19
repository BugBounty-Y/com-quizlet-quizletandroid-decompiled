package androidx.compose.material;

import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.C0242g;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0582z extends androidx.compose.ui.p implements InterfaceC0926w {
    public C0575s n;
    public C0281h o;
    public EnumC0320d0 p;
    public boolean q;

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.q = false;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(j2);
        if (!m.a0() || !this.q) {
            Pair pair = (Pair) this.o.invoke(new androidx.compose.ui.unit.j(R5.a(wB.a, wB.b)), new androidx.compose.ui.unit.a(j2));
            C0575s c0575s = this.n;
            G g = (G) pair.a;
            if (!Intrinsics.b(c0575s.d(), g)) {
                ((L0) c0575s.l).setValue(g);
                Object obj = pair.b;
                C0242g c0242g = new C0242g(10, c0575s, obj);
                kotlinx.coroutines.sync.c cVar = c0575s.d.b;
                boolean zE = cVar.e();
                if (zE) {
                    try {
                        c0242g.invoke();
                    } finally {
                        cVar.f(null);
                    }
                }
                if (!zE) {
                    c0575s.i(obj);
                }
            }
        }
        this.q = m.a0() || this.q;
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.activity.compose.g(m, this, wB, 15));
    }
}
