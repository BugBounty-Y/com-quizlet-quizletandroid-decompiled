package androidx.compose.material3;

import androidx.compose.foundation.InterfaceC0461p0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.InterfaceC0917m;

/* renamed from: androidx.compose.material3.p3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0702p3 implements InterfaceC0461p0 {
    public final boolean a;
    public final float b;
    public final long c;

    public C0702p3(boolean z, float f, long j) {
        this.a = z;
        this.b = f;
        this.c = j;
    }

    @Override // androidx.compose.foundation.InterfaceC0461p0
    public final InterfaceC0917m b(androidx.compose.foundation.interaction.k kVar) {
        C0597c1 c0597c1 = new C0597c1(this, 1);
        return new C0609e1(kVar, this.a, this.b, c0597c1);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0702p3)) {
            return false;
        }
        C0702p3 c0702p3 = (C0702p3) obj;
        if (this.a == c0702p3.a && androidx.compose.ui.unit.e.a(this.b, c0702p3.b)) {
            return C0861v.c(this.c, c0702p3.c);
        }
        return false;
    }

    public final int hashCode() {
        int iB = android.support.v4.media.session.a.b(Boolean.hashCode(this.a) * 31, this.b, 961);
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.c) + iB;
    }
}
