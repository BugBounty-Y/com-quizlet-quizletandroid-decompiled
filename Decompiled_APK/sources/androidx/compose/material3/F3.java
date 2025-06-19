package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F3 {
    public final boolean a;
    public final androidx.work.impl.model.t b;

    public F3(boolean z, androidx.compose.ui.unit.b bVar, G3 g3, Function1 function1) {
        this.a = z;
        if (z && g3 == G3.c) {
            throw new IllegalArgumentException("The initial value must not be set to PartiallyExpanded if skipPartiallyExpanded is set to true.");
        }
        int i = 1;
        this.b = new androidx.work.impl.model.t(g3, new androidx.compose.material.c0(bVar, i), new androidx.compose.material.d0(bVar, i), E3.a, function1);
    }

    public static Object a(F3 f3, G3 g3, kotlin.coroutines.jvm.internal.i iVar) {
        Object objC = AbstractC0646j.c(f3.b, g3, ((androidx.compose.runtime.F0) f3.b.k).i(), iVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    public final Object b(kotlin.coroutines.jvm.internal.i iVar) {
        Object objA = a(this, G3.a, iVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    public final boolean c() {
        return ((androidx.compose.runtime.L0) ((InterfaceC0773a0) this.b.g)).getValue() != G3.a;
    }

    public final Object d(kotlin.coroutines.jvm.internal.i iVar) {
        if (this.a) {
            throw new IllegalStateException("Attempted to animate to partial expanded when skipPartiallyExpanded was enabled. Set skipPartiallyExpanded to false to use this function.");
        }
        Object objA = a(this, G3.c, iVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }
}
