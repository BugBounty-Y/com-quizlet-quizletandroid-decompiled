package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N0 implements androidx.compose.ui.modifier.c, androidx.compose.ui.modifier.f {
    public final InterfaceC0773a0 b = C0776c.z(new Q());
    public final C0416v0 c;

    public N0(C0416v0 c0416v0) {
        this.c = c0416v0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof N0) {
            return Intrinsics.b(((N0) obj).c, this.c);
        }
        return false;
    }

    @Override // androidx.compose.ui.modifier.f
    public final androidx.compose.ui.modifier.h getKey() {
        return U0.a;
    }

    @Override // androidx.compose.ui.modifier.f
    public final Object getValue() {
        return (R0) ((androidx.compose.runtime.L0) this.b).getValue();
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    @Override // androidx.compose.ui.modifier.c
    public final void j(androidx.compose.ui.modifier.g gVar) {
        ((androidx.compose.runtime.L0) this.b).setValue(new M0(this.c, (R0) gVar.d(U0.a)));
    }
}
