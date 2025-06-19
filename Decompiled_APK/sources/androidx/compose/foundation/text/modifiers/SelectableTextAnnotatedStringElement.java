package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.T;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.L;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class SelectableTextAnnotatedStringElement extends T {
    public final C0995g b;
    public final L c;
    public final androidx.compose.ui.text.font.i d;
    public final Function1 e;
    public final int f;
    public final boolean g;
    public final int h;
    public final int i;
    public final List j;
    public final Function1 k;
    public final h l;

    public SelectableTextAnnotatedStringElement(C0995g c0995g, L l, androidx.compose.ui.text.font.i iVar, Function1 function1, int i, boolean z, int i2, int i3, List list, Function1 function12, h hVar) {
        this.b = c0995g;
        this.c = l;
        this.d = iVar;
        this.e = function1;
        this.f = i;
        this.g = z;
        this.h = i2;
        this.i = i3;
        this.j = list;
        this.k = function12;
        this.l = hVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SelectableTextAnnotatedStringElement)) {
            return false;
        }
        SelectableTextAnnotatedStringElement selectableTextAnnotatedStringElement = (SelectableTextAnnotatedStringElement) obj;
        selectableTextAnnotatedStringElement.getClass();
        return Intrinsics.b(this.b, selectableTextAnnotatedStringElement.b) && Intrinsics.b(this.c, selectableTextAnnotatedStringElement.c) && Intrinsics.b(this.j, selectableTextAnnotatedStringElement.j) && Intrinsics.b(this.d, selectableTextAnnotatedStringElement.d) && this.e == selectableTextAnnotatedStringElement.e && this.f == selectableTextAnnotatedStringElement.f && this.g == selectableTextAnnotatedStringElement.g && this.h == selectableTextAnnotatedStringElement.h && this.i == selectableTextAnnotatedStringElement.i && this.k == selectableTextAnnotatedStringElement.k && Intrinsics.b(this.l, selectableTextAnnotatedStringElement.l);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31;
        Function1 function1 = this.e;
        int iG = (((d0.g(d0.b(this.f, (iHashCode + (function1 != null ? function1.hashCode() : 0)) * 31, 31), 31, this.g) + this.h) * 31) + this.i) * 31;
        List list = this.j;
        int iHashCode2 = (iG + (list != null ? list.hashCode() : 0)) * 31;
        Function1 function12 = this.k;
        int iHashCode3 = (iHashCode2 + (function12 != null ? function12.hashCode() : 0)) * 31;
        h hVar = this.l;
        return (iHashCode3 + (hVar != null ? hVar.hashCode() : 0)) * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new f(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        boolean z;
        f fVar = (f) pVar;
        m mVar = fVar.q;
        L l = mVar.o;
        L l2 = this.c;
        if (l2 != l) {
            if (!l2.a.b(l.a)) {
                z = true;
            }
            boolean zR0 = mVar.R0(this.b);
            boolean zQ0 = fVar.q.Q0(l2, this.j, this.i, this.h, this.g, this.d, this.f);
            Function1 function1 = this.e;
            Function1 function12 = this.k;
            h hVar = this.l;
            mVar.M0(z, zR0, zQ0, mVar.P0(function1, function12, hVar, null));
            fVar.p = hVar;
            AbstractC0910f.o(fVar);
        }
        l2.getClass();
        z = false;
        boolean zR02 = mVar.R0(this.b);
        boolean zQ02 = fVar.q.Q0(l2, this.j, this.i, this.h, this.g, this.d, this.f);
        Function1 function13 = this.e;
        Function1 function122 = this.k;
        h hVar2 = this.l;
        mVar.M0(z, zR02, zQ02, mVar.P0(function13, function122, hVar2, null));
        fVar.p = hVar2;
        AbstractC0910f.o(fVar);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectableTextAnnotatedStringElement(text=");
        sb.append((Object) this.b);
        sb.append(", style=");
        sb.append(this.c);
        sb.append(", fontFamilyResolver=");
        sb.append(this.d);
        sb.append(", onTextLayout=");
        sb.append(this.e);
        sb.append(", overflow=");
        int i = this.f;
        sb.append((Object) (i == 1 ? "Clip" : i == 2 ? "Ellipsis" : i == 3 ? "Visible" : "Invalid"));
        sb.append(", softWrap=");
        sb.append(this.g);
        sb.append(", maxLines=");
        sb.append(this.h);
        sb.append(", minLines=");
        sb.append(this.i);
        sb.append(", placeholders=");
        sb.append(this.j);
        sb.append(", onPlaceholderLayout=");
        sb.append(this.k);
        sb.append(", selectionController=");
        sb.append(this.l);
        sb.append(", color=null)");
        return sb.toString();
    }
}
