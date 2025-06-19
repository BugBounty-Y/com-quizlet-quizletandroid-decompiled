package androidx.compose.ui.window;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class r {
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public r(int i) {
        boolean z = (i & 1) != 0;
        boolean z2 = (i & 2) != 0;
        boolean z3 = (i & 4) != 0;
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && this.b == rVar.b && this.c == rVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + d0.g((AbstractC0147y.k(1) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b)) * 31, 31, this.c);
    }
}
