package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.C0276z;

/* renamed from: androidx.compose.foundation.gestures.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0343p implements InterfaceC0314a0 {
    public C0276z a;
    public final C0338m0 b = AbstractC0349s0.b;

    public C0343p(C0276z c0276z) {
        this.a = c0276z;
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0314a0
    public final Object a(G0 g0, float f, kotlin.coroutines.h hVar) {
        return kotlinx.coroutines.E.J(this.b, new C0341o(f, this, g0, null), hVar);
    }
}
