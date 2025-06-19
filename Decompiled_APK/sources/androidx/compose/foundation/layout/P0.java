package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class P0 implements R0 {
    public final String a;
    public final InterfaceC0773a0 b;

    public P0(C0408r0 c0408r0, String str) {
        this.a = str;
        this.b = C0776c.z(c0408r0);
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

    public final C0408r0 e() {
        return (C0408r0) ((androidx.compose.runtime.L0) this.b).getValue();
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof P0) {
            return Intrinsics.b(e(), ((P0) obj).e());
        }
        return false;
    }

    public final void f(C0408r0 c0408r0) {
        ((androidx.compose.runtime.L0) this.b).setValue(c0408r0);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.a);
        sb.append("(left=");
        sb.append(e().a);
        sb.append(", top=");
        sb.append(e().b);
        sb.append(", right=");
        sb.append(e().c);
        sb.append(", bottom=");
        return android.support.v4.media.session.a.q(sb, e().d, ')');
    }
}
