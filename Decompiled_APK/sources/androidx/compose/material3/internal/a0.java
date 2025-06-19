package androidx.compose.material3.internal;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class a0 implements J {
    public final androidx.compose.ui.e a;

    public a0(androidx.compose.ui.e eVar) {
        this.a = eVar;
    }

    @Override // androidx.compose.material3.internal.J
    public final int a(androidx.compose.ui.unit.i iVar, long j, int i, androidx.compose.ui.unit.k kVar) {
        int i2 = (int) (j >> 32);
        if (i < i2) {
            return kotlin.ranges.l.c(this.a.a(i, i2, kVar), 0, i2 - i);
        }
        float f = (i2 - i) / 2.0f;
        androidx.compose.ui.unit.k kVar2 = androidx.compose.ui.unit.k.a;
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (kVar != kVar2) {
            f2 = DefinitionKt.NO_Float_VALUE * (-1);
        }
        return Math.round((1 + f2) * f);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof a0) {
            return this.a.equals(((a0) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(0) + (Float.hashCode(this.a.a) * 31);
    }

    public final String toString() {
        return "Horizontal(alignment=" + this.a + ", margin=0)";
    }
}
