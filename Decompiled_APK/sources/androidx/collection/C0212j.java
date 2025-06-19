package androidx.collection;

/* renamed from: androidx.collection.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0212j {
    public final long a;

    public static long a(int i, int i2) {
        return (i2 & 4294967295L) | (i << 32);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0212j) {
            return this.a == ((C0212j) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("(");
        long j = this.a;
        sb.append((int) (j >> 32));
        sb.append(", ");
        return android.support.v4.media.session.a.q(sb, (int) (j & 4294967295L), ')');
    }
}
