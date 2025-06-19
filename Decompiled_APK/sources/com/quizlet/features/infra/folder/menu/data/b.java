package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements g {
    public final long a;
    public final String b;
    public final boolean c;
    public final List d;

    public b(long j, String label, boolean z, List tags) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.a = j;
        this.b = label;
        this.c = z;
        this.d = tags;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1484183033);
        c0814p.p(false);
        return this.b;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final boolean b() {
        return this.c;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String c(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1992410565);
        String strH = z ? Z.h(c0814p, -1077982941, R.string.checked_a11y, c0814p, false) : Z.h(c0814p, -1077980731, R.string.unchecked_a11y, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final androidx.compose.ui.graphics.painter.b d(boolean z, InterfaceC0806l interfaceC0806l) {
        androidx.compose.ui.graphics.painter.b bVarD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-480004659);
        if (z) {
            c0814p.X(1294576301);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            bVarD = com.quizlet.ui.resources.icons.d.s(c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(1294578177);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-548615666);
            bVarD = Z.d(R.drawable.ic_sys_circle, c0814p, 0, false, false);
        }
        c0814p.p(false);
        return bVarD;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && this.c == bVar.c && Intrinsics.b(this.d, bVar.d);
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final long getId() {
        return this.a;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Folder(id=");
        sb.append(this.a);
        sb.append(", label=");
        sb.append(this.b);
        sb.append(", selected=");
        sb.append(this.c);
        sb.append(", tags=");
        return android.support.v4.media.session.a.n(")", sb, this.d);
    }
}
