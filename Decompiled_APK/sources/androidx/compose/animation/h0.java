package androidx.compose.animation;

import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public abstract class h0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public final /* synthetic */ int n;

    public abstract long M0(androidx.compose.ui.layout.J j, long j2);

    public abstract boolean N0();

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        switch (this.n) {
        }
        return j.z(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        switch (this.n) {
        }
        return j.x(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        switch (this.n) {
        }
        return j.X(i);
    }

    public androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        long jM0 = M0(j, j2);
        if (N0()) {
            jM0 = L5.j(j2, jM0);
        }
        androidx.compose.ui.layout.W wB = j.B(jM0);
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new C(wB, 6));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        switch (this.n) {
        }
        return j.b(i);
    }
}
