package androidx.navigation.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.navigation.C1291m;
import androidx.navigation.C1295q;
import androidx.navigation.V;
import androidx.navigation.W;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.b0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

@V("composable")
@Metadata
/* renamed from: androidx.navigation.compose.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1276i extends W {
    public final InterfaceC0773a0 c;

    public C1276i() {
        Intrinsics.checkNotNullParameter("composable", "name");
        this.c = C0776c.z(Boolean.FALSE);
    }

    @Override // androidx.navigation.W
    public final androidx.navigation.B a() {
        return new C1275h(this, AbstractC1270c.a);
    }

    @Override // androidx.navigation.W
    public final void d(List list, androidx.navigation.K k) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            b().g((C1291m) it2.next());
        }
        ((L0) this.c).setValue(Boolean.FALSE);
    }

    @Override // androidx.navigation.W
    public final void f(C1291m c1291m, boolean z) {
        b().e(c1291m, z);
        ((L0) this.c).setValue(Boolean.TRUE);
    }

    public final void h(C1291m entry) {
        C1295q c1295qB = b();
        Intrinsics.checkNotNullParameter(entry, "entry");
        Intrinsics.checkNotNullParameter(entry, "entry");
        s0 s0Var = c1295qB.c;
        s0Var.m(null, b0.g((Set) s0Var.getValue(), entry));
        androidx.navigation.internal.j jVar = c1295qB.h.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(entry, "entry");
        if (!jVar.f.contains(entry)) {
            throw new IllegalStateException("Cannot transition entry that is not in the back stack");
        }
        entry.a(androidx.lifecycle.B.d);
    }
}
