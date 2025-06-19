package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements f {
    public final long a;
    public final long b;
    public final String c;
    public final boolean d;

    public e(long j, long j2, String label, boolean z) {
        Intrinsics.checkNotNullParameter(label, "label");
        this.a = j;
        this.b = j2;
        this.c = label;
        this.d = z;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1693701112);
        c0814p.p(false);
        return this.c;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final boolean b() {
        return this.d;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String c(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-713250988);
        String strH = z ? Z.h(c0814p, -455896706, R.string.checked_a11y, c0814p, false) : Z.h(c0814p, -455894368, R.string.unchecked_a11y, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final androidx.compose.ui.graphics.painter.b d(boolean z, InterfaceC0806l interfaceC0806l) {
        androidx.compose.ui.graphics.painter.b bVarD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(327388802);
        if (z) {
            c0814p.X(1888368136);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            bVarD = com.quizlet.ui.resources.icons.d.s(c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(1888370140);
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
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b && Intrinsics.b(this.c, eVar.c) && this.d == eVar.d;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final long getId() {
        return this.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.e(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SubFolder(parentFolderId=");
        sb.append(this.a);
        sb.append(", id=");
        sb.append(this.b);
        sb.append(", label=");
        sb.append(this.c);
        sb.append(", selected=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
