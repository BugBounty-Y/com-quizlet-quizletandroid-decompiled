package androidx.compose.material3.internal;

import androidx.compose.animation.core.C0242g;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Pair;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.internal.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0660y extends androidx.compose.ui.p implements InterfaceC0926w {
    public androidx.work.impl.model.t n;
    public Function2 o;
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
            androidx.work.impl.model.t tVar = this.n;
            F f = (F) pair.a;
            if (!Intrinsics.b(tVar.h(), f)) {
                ((L0) ((InterfaceC0773a0) tVar.m)).setValue(f);
                Object obj = pair.b;
                C0242g c0242g = new C0242g(15, tVar, obj);
                kotlinx.coroutines.sync.c cVar = ((E) tVar.e).b;
                boolean zE = cVar.e();
                if (zE) {
                    try {
                        c0242g.invoke();
                    } finally {
                        cVar.f(null);
                    }
                }
                if (!zE) {
                    tVar.v(obj);
                }
            }
        }
        this.q = m.a0() || this.q;
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new androidx.activity.compose.g(m, this, wB, 19));
    }
}
