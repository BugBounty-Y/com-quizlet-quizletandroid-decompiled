package coil3.network;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t {
    public final int a;
    public final long b;
    public final long c;
    public final r d;
    public final u e;
    public final Object f;

    public t(int i, long j, long j2, r rVar, u uVar, Object obj) {
        this.a = i;
        this.b = j;
        this.c = j2;
        this.d = rVar;
        this.e = uVar;
        this.f = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return this.a == tVar.a && this.b == tVar.b && this.c == tVar.c && Intrinsics.b(this.d, tVar.d) && Intrinsics.b(this.e, tVar.e) && Intrinsics.b(this.f, tVar.f);
    }

    public final int hashCode() {
        int iD = assistantMode.refactored.a.d(d0.d(d0.d(this.a * 31, 31, this.b), 31, this.c), 31, this.d.a);
        u uVar = this.e;
        int iHashCode = (iD + (uVar == null ? 0 : uVar.a.hashCode())) * 31;
        Object obj = this.f;
        return iHashCode + (obj != null ? obj.hashCode() : 0);
    }

    public final String toString() {
        return "NetworkResponse(code=" + this.a + ", requestMillis=" + this.b + ", responseMillis=" + this.c + ", headers=" + this.d + ", body=" + this.e + ", delegate=" + this.f + ')';
    }
}
