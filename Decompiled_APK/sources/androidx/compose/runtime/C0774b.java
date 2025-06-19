package androidx.compose.runtime;

/* renamed from: androidx.compose.runtime.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0774b {
    public int a;

    public C0774b(int i) {
        this.a = i;
    }

    public final boolean a() {
        return this.a != Integer.MIN_VALUE;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append("{ location = ");
        return android.support.v4.media.session.a.r(sb, this.a, " }");
    }
}
