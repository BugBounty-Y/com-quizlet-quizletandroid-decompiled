package androidx.paging;

/* loaded from: classes.dex */
public final class i1 extends k1 {
    public final int e;
    public final int f;

    public i1(int i, int i2, int i3, int i4, int i5, int i6) {
        super(i3, i4, i5, i6);
        this.e = i;
        this.f = i2;
    }

    @Override // androidx.paging.k1
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i1)) {
            return false;
        }
        i1 i1Var = (i1) obj;
        if (this.e == i1Var.e && this.f == i1Var.f) {
            if (this.a == i1Var.a) {
                if (this.b == i1Var.b) {
                    if (this.c == i1Var.c) {
                        if (this.d == i1Var.d) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override // androidx.paging.k1
    public final int hashCode() {
        return Integer.hashCode(this.f) + Integer.hashCode(this.e) + super.hashCode();
    }

    public final String toString() {
        return kotlin.text.x.d("ViewportHint.Access(\n            |    pageOffset=" + this.e + ",\n            |    indexInPage=" + this.f + ",\n            |    presentedItemsBefore=" + this.a + ",\n            |    presentedItemsAfter=" + this.b + ",\n            |    originalPageOffsetFirst=" + this.c + ",\n            |    originalPageOffsetLast=" + this.d + ",\n            |)");
    }
}
