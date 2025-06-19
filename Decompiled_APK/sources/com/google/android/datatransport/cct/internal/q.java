package com.google.android.datatransport.cct.internal;

/* loaded from: classes2.dex */
public final class q extends D {
    public final Integer a;

    public q(Integer num) {
        this.a = num;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        Integer num = this.a;
        q qVar = (q) ((D) obj);
        return num == null ? qVar.a == null : num.equals(qVar.a);
    }

    public final int hashCode() {
        Integer num = this.a;
        return (num == null ? 0 : num.hashCode()) ^ 1000003;
    }

    public final String toString() {
        return assistantMode.refactored.a.l(new StringBuilder("ExternalPRequestContext{originAssociatedProductId="), this.a, "}");
    }
}
