package androidx.compose.runtime.changelist;

import androidx.compose.animation.core.U0;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;

/* renamed from: androidx.compose.runtime.changelist.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0783f extends J {
    public static final C0783f c = new C0783f(0, 2, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        androidx.compose.runtime.internal.f fVar = (androidx.compose.runtime.internal.f) k.f(1);
        int i = fVar != null ? fVar.a : 0;
        C0778a c0778a = (C0778a) k.f(0);
        if (i > 0) {
            interfaceC0790d = new U0(interfaceC0790d, i);
        }
        c0778a.b(interfaceC0790d, d0, jVar);
    }
}
