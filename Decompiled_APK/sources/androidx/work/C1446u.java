package androidx.work;

/* renamed from: androidx.work.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1446u extends x {
    public final C1437k a = C1437k.b;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1446u.class != obj.getClass()) {
            return false;
        }
        return this.a.equals(((C1446u) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode() + (C1446u.class.getName().hashCode() * 31);
    }

    public final String toString() {
        return "Failure {mOutputData=" + this.a + '}';
    }
}
