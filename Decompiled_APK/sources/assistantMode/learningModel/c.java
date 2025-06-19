package assistantMode.learningModel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final Double a;
    public final double b;

    public c(Double d, double d2) {
        this.a = d;
        this.b = d2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Double.compare(this.b, cVar.b) == 0;
    }

    public final int hashCode() {
        Double d = this.a;
        return Double.hashCode(this.b) + ((d == null ? 0 : d.hashCode()) * 31);
    }

    public final String toString() {
        return "DecayConstants(tau=" + this.a + ", scale=" + this.b + ")";
    }
}
