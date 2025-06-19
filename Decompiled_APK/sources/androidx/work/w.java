package androidx.work;

/* loaded from: classes.dex */
public final class w extends x {
    public final C1437k a;

    public w(C1437k c1437k) {
        this.a = c1437k;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || w.class != obj.getClass()) {
            return false;
        }
        return this.a.equals(((w) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode() + (w.class.getName().hashCode() * 31);
    }

    public final String toString() {
        return "Success {mOutputData=" + this.a + '}';
    }
}
