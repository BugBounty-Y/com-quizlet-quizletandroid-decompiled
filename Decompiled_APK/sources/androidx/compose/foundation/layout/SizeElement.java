package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class SizeElement extends androidx.compose.ui.node.T {
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final boolean f;

    public SizeElement(float f, float f2, float f3, float f4, boolean z) {
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SizeElement)) {
            return false;
        }
        SizeElement sizeElement = (SizeElement) obj;
        return androidx.compose.ui.unit.e.a(this.b, sizeElement.b) && androidx.compose.ui.unit.e.a(this.c, sizeElement.c) && androidx.compose.ui.unit.e.a(this.d, sizeElement.d) && androidx.compose.ui.unit.e.a(this.e, sizeElement.e) && this.f == sizeElement.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.b) * 31, this.c, 31), this.d, 31), this.e, 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        L0 l0 = new L0();
        l0.n = this.b;
        l0.o = this.c;
        l0.p = this.d;
        l0.q = this.e;
        l0.r = this.f;
        return l0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        L0 l0 = (L0) pVar;
        l0.n = this.b;
        l0.o = this.c;
        l0.p = this.d;
        l0.q = this.e;
        l0.r = this.f;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ SizeElement(float f, float f2, float f3, float f4, boolean z, int i) {
        boolean z2;
        float f5;
        f = (i & 1) != 0 ? Float.NaN : f;
        f2 = (i & 2) != 0 ? Float.NaN : f2;
        f3 = (i & 4) != 0 ? Float.NaN : f3;
        if ((i & 8) != 0) {
            z2 = z;
            f5 = Float.NaN;
        } else {
            z2 = z;
            f5 = f4;
        }
        this(f, f2, f3, f5, z2);
    }
}
