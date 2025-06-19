package androidx.compose.foundation.relocation;

import androidx.compose.ui.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends p {
    public c n;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        c cVar = this.n;
        if (cVar != null) {
            cVar.a.n(this);
        }
        if (cVar != null) {
            cVar.a.b(this);
        }
        this.n = cVar;
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        c cVar = this.n;
        if (cVar != null) {
            Intrinsics.e(cVar, "null cannot be cast to non-null type androidx.compose.foundation.relocation.BringIntoViewRequesterImpl");
            cVar.a.n(this);
        }
    }
}
