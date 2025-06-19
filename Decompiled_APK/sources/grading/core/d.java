package grading.core;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class d {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;

    public d(boolean z, boolean z2, boolean z3, boolean z4) {
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
    }

    public static d a(d dVar, int i) {
        boolean z = dVar.a;
        boolean z2 = (i & 2) != 0 ? dVar.b : true;
        boolean z3 = (i & 4) != 0 ? dVar.c : false;
        boolean z4 = dVar.d;
        dVar.getClass();
        return new d(z, z2, z3, z4);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && this.c == dVar.c && this.d == dVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "GradingSettings(acceptsPartialAnswer=" + this.a + ", acceptsAnswersWithTypos=" + this.b + ", acceptsSmartGrading=" + this.c + ", allowsRetry=" + this.d + ")";
    }

    public /* synthetic */ d(boolean z, boolean z2, boolean z3, boolean z4, int i) {
        this((i & 1) != 0 ? false : z, (i & 2) != 0 ? false : z2, (i & 4) != 0 ? false : z3, (i & 8) != 0 ? false : z4);
    }
}
