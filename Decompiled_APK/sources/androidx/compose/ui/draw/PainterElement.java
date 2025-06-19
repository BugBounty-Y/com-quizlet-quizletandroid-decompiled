package androidx.compose.ui.draw;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class PainterElement extends T {
    public final androidx.compose.ui.graphics.painter.b b;
    public final androidx.compose.ui.d c;
    public final InterfaceC0889j d;
    public final float e;
    public final AbstractC0874w f;

    public PainterElement(androidx.compose.ui.graphics.painter.b bVar, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, float f, AbstractC0874w abstractC0874w) {
        this.b = bVar;
        this.c = dVar;
        this.d = interfaceC0889j;
        this.e = f;
        this.f = abstractC0874w;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PainterElement)) {
            return false;
        }
        PainterElement painterElement = (PainterElement) obj;
        return Intrinsics.b(this.b, painterElement.b) && Intrinsics.b(this.c, painterElement.c) && Intrinsics.b(this.d, painterElement.d) && Float.compare(this.e, painterElement.e) == 0 && Intrinsics.b(this.f, painterElement.f);
    }

    public final int hashCode() {
        int iB = android.support.v4.media.session.a.b((this.d.hashCode() + ((this.c.hashCode() + d0.g(this.b.hashCode() * 31, 31, true)) * 31)) * 31, this.e, 31);
        AbstractC0874w abstractC0874w = this.f;
        return iB + (abstractC0874w == null ? 0 : abstractC0874w.hashCode());
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        j jVar = new j();
        jVar.n = this.b;
        jVar.o = true;
        jVar.p = this.c;
        jVar.q = this.d;
        jVar.r = this.e;
        jVar.s = this.f;
        return jVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        j jVar = (j) pVar;
        boolean z = jVar.o;
        androidx.compose.ui.graphics.painter.b bVar = this.b;
        boolean z2 = (z && androidx.compose.ui.geometry.e.a(jVar.n.h(), bVar.h())) ? false : true;
        jVar.n = bVar;
        jVar.o = true;
        jVar.p = this.c;
        jVar.q = this.d;
        jVar.r = this.e;
        jVar.s = this.f;
        if (z2) {
            AbstractC0910f.o(jVar);
        }
        AbstractC0910f.n(jVar);
    }

    public final String toString() {
        return "PainterElement(painter=" + this.b + ", sizeToIntrinsics=true, alignment=" + this.c + ", contentScale=" + this.d + ", alpha=" + this.e + ", colorFilter=" + this.f + ')';
    }
}
