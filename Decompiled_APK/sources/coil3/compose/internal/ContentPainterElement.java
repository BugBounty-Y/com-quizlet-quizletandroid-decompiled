package coil3.compose.internal;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import coil3.compose.j;
import coil3.m;
import coil3.size.i;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ContentPainterElement extends T {
    public final coil3.request.g b;
    public final m c;
    public final coil3.compose.b d;
    public final Function1 e;
    public final Function1 f;
    public final androidx.compose.ui.d g;
    public final InterfaceC0889j h;
    public final AbstractC0874w i;
    public final coil3.compose.m j;
    public final String k;

    public ContentPainterElement(coil3.request.g gVar, m mVar, coil3.compose.b bVar, Function1 function1, Function1 function12, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, AbstractC0874w abstractC0874w, coil3.compose.m mVar2, String str) {
        this.b = gVar;
        this.c = mVar;
        this.d = bVar;
        this.e = function1;
        this.f = function12;
        this.g = dVar;
        this.h = interfaceC0889j;
        this.i = abstractC0874w;
        this.j = mVar2;
        this.k = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ContentPainterElement)) {
            return false;
        }
        ContentPainterElement contentPainterElement = (ContentPainterElement) obj;
        return this.b.equals(contentPainterElement.b) && this.c.equals(contentPainterElement.c) && Intrinsics.b(this.d, contentPainterElement.d) && Intrinsics.b(this.e, contentPainterElement.e) && Intrinsics.b(this.f, contentPainterElement.f) && Intrinsics.b(this.g, contentPainterElement.g) && Intrinsics.b(this.h, contentPainterElement.h) && Float.compare(1.0f, 1.0f) == 0 && Intrinsics.b(this.i, contentPainterElement.i) && Intrinsics.b(this.j, contentPainterElement.j) && Intrinsics.b(this.k, contentPainterElement.k);
    }

    public final int hashCode() {
        int iHashCode = (this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31)) * 31;
        Function1 function1 = this.f;
        int iB = android.support.v4.media.session.a.b((this.h.hashCode() + ((this.g.hashCode() + d0.b(1, (iHashCode + (function1 == null ? 0 : function1.hashCode())) * 31, 31)) * 31)) * 31, 1.0f, 31);
        AbstractC0874w abstractC0874w = this.i;
        int iG = d0.g((iB + (abstractC0874w == null ? 0 : abstractC0874w.hashCode())) * 31, 31, true);
        coil3.compose.m mVar = this.j;
        int iHashCode2 = (iG + (mVar == null ? 0 : mVar.hashCode())) * 31;
        String str = this.k;
        return iHashCode2 + (str != null ? str.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        m mVar = this.c;
        coil3.request.g gVar = this.b;
        coil3.compose.c cVar = new coil3.compose.c(mVar, gVar, this.d);
        j jVar = new j(cVar);
        jVar.m = this.e;
        jVar.n = this.f;
        jVar.o = this.h;
        jVar.p = 1;
        jVar.q = this.j;
        jVar.m(cVar);
        i iVar = gVar.o;
        return new b(jVar, this.g, this.h, this.i, this.k, iVar instanceof coil3.compose.p ? (coil3.compose.p) iVar : null);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        b bVar = (b) pVar;
        long jH = bVar.u.h();
        coil3.compose.p pVar2 = bVar.t;
        m mVar = this.c;
        coil3.request.g gVar = this.b;
        coil3.compose.c cVar = new coil3.compose.c(mVar, gVar, this.d);
        j jVar = bVar.u;
        jVar.m = this.e;
        jVar.n = this.f;
        InterfaceC0889j interfaceC0889j = this.h;
        jVar.o = interfaceC0889j;
        jVar.p = 1;
        jVar.q = this.j;
        jVar.m(cVar);
        boolean zA = androidx.compose.ui.geometry.e.a(jH, jVar.h());
        bVar.n = this.g;
        i iVar = gVar.o;
        bVar.t = iVar instanceof coil3.compose.p ? (coil3.compose.p) iVar : null;
        bVar.o = interfaceC0889j;
        bVar.p = 1.0f;
        bVar.q = this.i;
        bVar.r = true;
        String str = bVar.s;
        String str2 = this.k;
        if (!Intrinsics.b(str, str2)) {
            bVar.s = str2;
            AbstractC0910f.p(bVar);
        }
        boolean zB = Intrinsics.b(pVar2, bVar.t);
        if (!zA || !zB) {
            AbstractC0910f.o(bVar);
        }
        AbstractC0910f.n(bVar);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContentPainterElement(request=");
        sb.append(this.b);
        sb.append(", imageLoader=");
        sb.append(this.c);
        sb.append(", modelEqualityDelegate=");
        sb.append(this.d);
        sb.append(", transform=");
        sb.append(this.e);
        sb.append(", onState=");
        sb.append(this.f);
        sb.append(", filterQuality=");
        sb.append((Object) "Low");
        sb.append(", alignment=");
        sb.append(this.g);
        sb.append(", contentScale=");
        sb.append(this.h);
        sb.append(", alpha=1.0, colorFilter=");
        sb.append(this.i);
        sb.append(", clipToBounds=true, previewHandler=");
        sb.append(this.j);
        sb.append(", contentDescription=");
        return d0.r(sb, this.k, ')');
    }
}
