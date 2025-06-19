package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class B {
    public final boolean a;
    public final boolean b;

    public B(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return this.a == b.a && this.b == b.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "CheckEmail(isValid=" + this.a + ", hasExistingAccount=" + this.b + ")";
    }
}
