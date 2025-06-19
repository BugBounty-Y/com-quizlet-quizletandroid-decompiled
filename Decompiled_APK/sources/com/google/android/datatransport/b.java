package com.google.android.datatransport;

/* loaded from: classes2.dex */
public final class b {
    public final Integer a;

    public b(Integer num) {
        this.a = num;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        Integer num = this.a;
        return num == null ? bVar.a == null : num.equals(bVar.a);
    }

    public final int hashCode() {
        Integer num = this.a;
        return (num == null ? 0 : num.hashCode()) ^ 1000003;
    }

    public final String toString() {
        return assistantMode.refactored.a.l(new StringBuilder("ProductData{productId="), this.a, "}");
    }
}
