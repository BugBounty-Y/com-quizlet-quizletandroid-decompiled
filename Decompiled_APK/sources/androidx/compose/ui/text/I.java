package androidx.compose.ui.text;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I {
    public final D a;
    public final D b;
    public final D c;
    public final D d;

    public I(D d, D d2, D d3, D d4) {
        this.a = d;
        this.b = d2;
        this.c = d3;
        this.d = d4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return Intrinsics.b(this.a, i.a) && Intrinsics.b(this.b, i.b) && Intrinsics.b(this.c, i.c) && Intrinsics.b(this.d, i.d);
    }

    public final int hashCode() {
        D d = this.a;
        int iHashCode = (d != null ? d.hashCode() : 0) * 31;
        D d2 = this.b;
        int iHashCode2 = (iHashCode + (d2 != null ? d2.hashCode() : 0)) * 31;
        D d3 = this.c;
        int iHashCode3 = (iHashCode2 + (d3 != null ? d3.hashCode() : 0)) * 31;
        D d4 = this.d;
        return iHashCode3 + (d4 != null ? d4.hashCode() : 0);
    }
}
