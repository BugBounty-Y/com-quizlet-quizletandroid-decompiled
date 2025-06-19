package androidx.compose.foundation.text.selection;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.selection.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0536q {
    public final C0535p a;
    public final C0535p b;
    public final boolean c;

    public C0536q(C0535p c0535p, C0535p c0535p2, boolean z) {
        this.a = c0535p;
        this.b = c0535p2;
        this.c = z;
    }

    public static C0536q a(C0536q c0536q, C0535p c0535p, C0535p c0535p2, boolean z, int i) {
        if ((i & 1) != 0) {
            c0535p = c0536q.a;
        }
        if ((i & 2) != 0) {
            c0535p2 = c0536q.b;
        }
        if ((i & 4) != 0) {
            z = c0536q.c;
        }
        c0536q.getClass();
        return new C0536q(c0535p, c0535p2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0536q)) {
            return false;
        }
        C0536q c0536q = (C0536q) obj;
        return Intrinsics.b(this.a, c0536q.a) && Intrinsics.b(this.b, c0536q.b) && this.c == c0536q.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Selection(start=");
        sb.append(this.a);
        sb.append(", end=");
        sb.append(this.b);
        sb.append(", handlesCrossed=");
        return android.support.v4.media.session.a.u(sb, this.c, ')');
    }
}
