package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0416v0 implements R0 {
    public final R0 a;
    public final int b;

    public C0416v0(R0 r0, int i) {
        this.a = r0;
        this.b = i;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int a(androidx.compose.ui.unit.b bVar) {
        if ((this.b & 16) != 0) {
            return this.a.a(bVar);
        }
        return 0;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int b(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        if (((kVar == androidx.compose.ui.unit.k.a ? 4 : 1) & this.b) != 0) {
            return this.a.b(bVar, kVar);
        }
        return 0;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int c(androidx.compose.ui.unit.b bVar) {
        if ((this.b & 32) != 0) {
            return this.a.c(bVar);
        }
        return 0;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int d(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        if (((kVar == androidx.compose.ui.unit.k.a ? 8 : 2) & this.b) != 0) {
            return this.a.d(bVar, kVar);
        }
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0416v0)) {
            return false;
        }
        C0416v0 c0416v0 = (C0416v0) obj;
        if (Intrinsics.b(this.a, c0416v0.a)) {
            if (this.b == c0416v0.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("(");
        sb.append(this.a);
        sb.append(" only ");
        StringBuilder sb2 = new StringBuilder("WindowInsetsSides(");
        StringBuilder sb3 = new StringBuilder();
        int i = this.b;
        int i2 = AbstractC0382e.c;
        if ((i & i2) == i2) {
            AbstractC0382e.B("Start", sb3);
        }
        int i3 = AbstractC0382e.e;
        if ((i & i3) == i3) {
            AbstractC0382e.B("Left", sb3);
        }
        if ((i & 16) == 16) {
            AbstractC0382e.B("Top", sb3);
        }
        int i4 = AbstractC0382e.d;
        if ((i & i4) == i4) {
            AbstractC0382e.B("End", sb3);
        }
        int i5 = AbstractC0382e.f;
        if ((i & i5) == i5) {
            AbstractC0382e.B("Right", sb3);
        }
        if ((i & 32) == 32) {
            AbstractC0382e.B("Bottom", sb3);
        }
        String string = sb3.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        sb2.append(string);
        sb2.append(')');
        sb.append((Object) sb2.toString());
        sb.append(')');
        return sb.toString();
    }
}
