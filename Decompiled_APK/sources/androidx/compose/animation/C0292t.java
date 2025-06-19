package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.x0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;

/* renamed from: androidx.compose.animation.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0292t implements x0 {
    public final E0 a;
    public androidx.compose.ui.d b;
    public final InterfaceC0773a0 c = C0776c.z(new androidx.compose.ui.unit.j(0));
    public final androidx.collection.I d;

    public C0292t(E0 e0, androidx.compose.ui.d dVar) {
        this.a = e0;
        this.b = dVar;
        long[] jArr = androidx.collection.S.a;
        this.d = new androidx.collection.I();
    }

    @Override // androidx.compose.animation.core.x0
    public final Object a() {
        return this.a.f().a();
    }

    @Override // androidx.compose.animation.core.x0
    public final Object c() {
        return this.a.f().c();
    }
}
