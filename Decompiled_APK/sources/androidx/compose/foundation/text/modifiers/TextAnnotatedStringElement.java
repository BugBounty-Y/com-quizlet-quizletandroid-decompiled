package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.T;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.L;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class TextAnnotatedStringElement extends T {
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
    public final Function1 l;

    public TextAnnotatedStringElement(C0995g c0995g, L l, androidx.compose.ui.text.font.i iVar, Function1 function1, int i, boolean z, int i2, int i3, List list, Function1 function12, Function1 function13) {
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
        this.l = function13;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextAnnotatedStringElement)) {
            return false;
        }
        TextAnnotatedStringElement textAnnotatedStringElement = (TextAnnotatedStringElement) obj;
        textAnnotatedStringElement.getClass();
        return Intrinsics.b(this.b, textAnnotatedStringElement.b) && Intrinsics.b(this.c, textAnnotatedStringElement.c) && Intrinsics.b(this.j, textAnnotatedStringElement.j) && Intrinsics.b(this.d, textAnnotatedStringElement.d) && this.e == textAnnotatedStringElement.e && this.l == textAnnotatedStringElement.l && this.f == textAnnotatedStringElement.f && this.g == textAnnotatedStringElement.g && this.h == textAnnotatedStringElement.h && this.i == textAnnotatedStringElement.i && this.k == textAnnotatedStringElement.k;
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31;
        Function1 function1 = this.e;
        int iG = (((d0.g(d0.b(this.f, (iHashCode + (function1 != null ? function1.hashCode() : 0)) * 31, 31), 31, this.g) + this.h) * 31) + this.i) * 31;
        List list = this.j;
        int iHashCode2 = (iG + (list != null ? list.hashCode() : 0)) * 31;
        Function1 function12 = this.k;
        int iHashCode3 = (iHashCode2 + (function12 != null ? function12.hashCode() : 0)) * 29791;
        Function1 function13 = this.l;
        return iHashCode3 + (function13 != null ? function13.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new m(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, null, this.l);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        boolean z;
        m mVar = (m) pVar;
        L l = mVar.o;
        L l2 = this.c;
        if (l2 != l) {
            if (!l2.a.b(l.a)) {
                z = true;
            }
            mVar.M0(z, mVar.R0(this.b), mVar.Q0(this.c, this.j, this.i, this.h, this.g, this.d, this.f), mVar.P0(this.e, this.k, null, this.l));
        }
        l2.getClass();
        z = false;
        mVar.M0(z, mVar.R0(this.b), mVar.Q0(this.c, this.j, this.i, this.h, this.g, this.d, this.f), mVar.P0(this.e, this.k, null, this.l));
    }
}
