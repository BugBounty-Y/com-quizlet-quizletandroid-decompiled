package androidx.compose.material3.internal;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class b0 implements K {
    public final androidx.compose.ui.h a;
    public final int b;

    public b0(androidx.compose.ui.h hVar, int i) {
        this.a = hVar;
        this.b = i;
    }

    @Override // androidx.compose.material3.internal.K
    public final int a(androidx.compose.ui.unit.i iVar, long j, int i) {
        int i2 = (int) (j & 4294967295L);
        int i3 = this.b;
        if (i < i2 - (i3 * 2)) {
            return kotlin.ranges.l.c(this.a.a(i, i2), i3, (i2 - i3) - i);
        }
        return Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i2 - i) / 2.0f));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b0)) {
            return false;
        }
        b0 b0Var = (b0) obj;
        return this.a.equals(b0Var.a) && this.b == b0Var.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Float.hashCode(this.a.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Vertical(alignment=");
        sb.append(this.a);
        sb.append(", margin=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
