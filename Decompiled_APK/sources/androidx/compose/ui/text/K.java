package androidx.compose.ui.text;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;

/* loaded from: classes.dex */
public final class K {
    public static final long b = AbstractC3205m5.c(0, 0);
    public static final /* synthetic */ int c = 0;
    public final long a;

    public /* synthetic */ K(long j) {
        this.a = j;
    }

    public static final boolean a(long j, long j2) {
        return j == j2;
    }

    public static final boolean b(long j) {
        return ((int) (j >> 32)) == ((int) (j & 4294967295L));
    }

    public static final int c(long j) {
        return d(j) - e(j);
    }

    public static final int d(long j) {
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        return i > i2 ? i : i2;
    }

    public static final int e(long j) {
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        return i > i2 ? i2 : i;
    }

    public static final boolean f(long j) {
        return ((int) (j >> 32)) > ((int) (j & 4294967295L));
    }

    public static String g(long j) {
        StringBuilder sb = new StringBuilder("TextRange(");
        sb.append((int) (j >> 32));
        sb.append(", ");
        return android.support.v4.media.session.a.q(sb, (int) (j & 4294967295L), ')');
    }

    public final boolean equals(Object obj) {
        if (obj instanceof K) {
            return this.a == ((K) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return g(this.a);
    }
}
