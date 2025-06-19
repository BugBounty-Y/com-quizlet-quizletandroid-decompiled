package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;

/* renamed from: androidx.compose.foundation.layout.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0378c implements R0 {
    public final int a;
    public final String b;
    public final InterfaceC0773a0 c = C0776c.z(androidx.core.graphics.e.e);
    public final InterfaceC0773a0 d = C0776c.z(Boolean.TRUE);

    public C0378c(int i, String str) {
        this.a = i;
        this.b = str;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int a(androidx.compose.ui.unit.b bVar) {
        return e().b;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int b(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return e().c;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int c(androidx.compose.ui.unit.b bVar) {
        return e().d;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int d(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return e().a;
    }

    public final androidx.core.graphics.e e() {
        return (androidx.core.graphics.e) ((androidx.compose.runtime.L0) this.c).getValue();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0378c) {
            return this.a == ((C0378c) obj).a;
        }
        return false;
    }

    public final void f(androidx.core.view.D0 d0, int i) {
        int i2 = this.a;
        if (i == 0 || (i & i2) != 0) {
            ((androidx.compose.runtime.L0) this.c).setValue(d0.a.g(i2));
            boolean zQ = d0.a.q(i2);
            ((androidx.compose.runtime.L0) this.d).setValue(Boolean.valueOf(zQ));
        }
    }

    public final int hashCode() {
        return this.a;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.b);
        sb.append('(');
        sb.append(e().a);
        sb.append(", ");
        sb.append(e().b);
        sb.append(", ");
        sb.append(e().c);
        sb.append(", ");
        return android.support.v4.media.session.a.q(sb, e().d, ')');
    }
}
