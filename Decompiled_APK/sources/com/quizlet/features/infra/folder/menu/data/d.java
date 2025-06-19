package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements f {
    public final long a;
    public final kotlinx.collections.immutable.e b;
    public final boolean c;

    public d(long j, kotlinx.collections.immutable.e currentTags, boolean z) {
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        this.a = j;
        this.b = currentTags;
        this.c = z;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        return Z.h(c0814p, 1608528795, R.string.new_tag_title, c0814p, false);
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final String c(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1777473511);
        c0814p.p(false);
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final androidx.compose.ui.graphics.painter.b d(boolean z, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-733382251);
        ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarF = com.quizlet.ui.resources.icons.d.F(c0814p);
        c0814p.p(false);
        return bVarF;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.g
    public final long getId() {
        return -1L;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Add(parentFolderId=");
        sb.append(this.a);
        sb.append(", currentTags=");
        sb.append(this.b);
        sb.append(", enabled=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
