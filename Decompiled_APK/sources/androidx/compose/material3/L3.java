package androidx.compose.material3;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class L3 {
    public final V3 a;
    public final C5028l b;

    public L3(V3 v3, C5028l c5028l) {
        this.a = v3;
        this.b = c5028l;
    }

    public final void a() {
        C5028l c5028l = this.b;
        if (c5028l.w()) {
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(U3.a);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || L3.class != obj.getClass()) {
            return false;
        }
        L3 l3 = (L3) obj;
        return Intrinsics.b(this.a, l3.a) && this.b.equals(l3.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }
}
