package androidx.compose.material3;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M3 implements V3 {
    public final String a;
    public final int b;

    public M3(String str, int i) {
        this.a = str;
        this.b = i;
    }

    @Override // androidx.compose.material3.V3
    public final String a() {
        return this.a;
    }

    @Override // androidx.compose.material3.V3
    public final String b() {
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || M3.class != obj.getClass()) {
            return false;
        }
        M3 m3 = (M3) obj;
        return Intrinsics.b(this.a, m3.a) && this.b == m3.b;
    }

    @Override // androidx.compose.material3.V3
    public final int getDuration() {
        return this.b;
    }

    public final int hashCode() {
        return AbstractC0147y.k(this.b) + androidx.compose.animation.d0.g(this.a.hashCode() * 961, 31, false);
    }
}
