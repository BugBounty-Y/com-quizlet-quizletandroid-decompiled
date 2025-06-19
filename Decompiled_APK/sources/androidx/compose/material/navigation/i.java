package androidx.compose.material.navigation;

import androidx.compose.animation.C0279f;
import androidx.compose.material.e0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.navigation.B;
import androidx.navigation.C1291m;
import androidx.navigation.C1295q;
import androidx.navigation.K;
import androidx.navigation.V;
import androidx.navigation.W;
import java.util.List;
import kotlin.Metadata;

@V("bottomSheet")
@Metadata
/* loaded from: classes.dex */
public final class i extends W {
    public final e0 c;
    public final InterfaceC0773a0 d = C0776c.z(Boolean.FALSE);
    public final androidx.compose.runtime.internal.d e = new androidx.compose.runtime.internal.d(true, -1433084388, new C0279f(this, 8));

    public i(e0 e0Var) {
        this.c = e0Var;
    }

    @Override // androidx.navigation.W
    public final B a() {
        return new b(this, l.a);
    }

    @Override // androidx.navigation.W
    public final void d(List list, K k) {
        int size = list.size();
        for (int i = 0; i < size; i++) {
            b().g((C1291m) list.get(i));
        }
    }

    @Override // androidx.navigation.W
    public final void e(C1295q c1295q) {
        super.e(c1295q);
        ((L0) this.d).setValue(Boolean.TRUE);
    }

    @Override // androidx.navigation.W
    public final void f(C1291m c1291m, boolean z) {
        b().e(c1291m, z);
    }
}
