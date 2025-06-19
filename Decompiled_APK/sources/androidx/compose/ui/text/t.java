package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t {
    public final int a;
    public final int b;
    public final long c;
    public final androidx.compose.ui.text.style.p d;
    public final w e;
    public final androidx.compose.ui.text.style.g f;
    public final int g;
    public final int h;
    public final androidx.compose.ui.text.style.q i;

    public t(int i, int i2, long j, androidx.compose.ui.text.style.p pVar, w wVar, androidx.compose.ui.text.style.g gVar, int i3, int i4, androidx.compose.ui.text.style.q qVar) {
        this.a = i;
        this.b = i2;
        this.c = j;
        this.d = pVar;
        this.e = wVar;
        this.f = gVar;
        this.g = i3;
        this.h = i4;
        this.i = qVar;
        if (androidx.compose.ui.unit.m.a(j, androidx.compose.ui.unit.m.c) || androidx.compose.ui.unit.m.c(j) >= DefinitionKt.NO_Float_VALUE) {
            return;
        }
        throw new IllegalStateException(("lineHeight can't be negative (" + androidx.compose.ui.unit.m.c(j) + ')').toString());
    }

    public final t a(t tVar) {
        if (tVar == null) {
            return this;
        }
        return u.a(this, tVar.a, tVar.b, tVar.c, tVar.d, tVar.e, tVar.f, tVar.g, tVar.h, tVar.i);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return this.a == tVar.a && this.b == tVar.b && androidx.compose.ui.unit.m.a(this.c, tVar.c) && Intrinsics.b(this.d, tVar.d) && Intrinsics.b(this.e, tVar.e) && Intrinsics.b(this.f, tVar.f) && this.g == tVar.g && this.h == tVar.h && Intrinsics.b(this.i, tVar.i);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        int iD = d0.d(iB, 31, this.c);
        androidx.compose.ui.text.style.p pVar = this.d;
        int iHashCode = (iD + (pVar != null ? pVar.hashCode() : 0)) * 31;
        w wVar = this.e;
        int iHashCode2 = (iHashCode + (wVar != null ? wVar.hashCode() : 0)) * 31;
        androidx.compose.ui.text.style.g gVar = this.f;
        int iB2 = d0.b(this.h, d0.b(this.g, (iHashCode2 + (gVar != null ? gVar.hashCode() : 0)) * 31, 31), 31);
        androidx.compose.ui.text.style.q qVar = this.i;
        return iB2 + (qVar != null ? qVar.hashCode() : 0);
    }

    public final String toString() {
        return "ParagraphStyle(textAlign=" + ((Object) androidx.compose.ui.text.style.i.a(this.a)) + ", textDirection=" + ((Object) androidx.compose.ui.text.style.k.a(this.b)) + ", lineHeight=" + ((Object) androidx.compose.ui.unit.m.d(this.c)) + ", textIndent=" + this.d + ", platformStyle=" + this.e + ", lineHeightStyle=" + this.f + ", lineBreak=" + ((Object) androidx.compose.ui.text.style.e.a(this.g)) + ", hyphens=" + ((Object) androidx.compose.ui.text.style.d.a(this.h)) + ", textMotion=" + this.i + ')';
    }
}
