package androidx.camera.core;

import android.graphics.Matrix;
import androidx.camera.core.impl.v0;

/* renamed from: androidx.camera.core.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0154f implements M {
    public final v0 a;
    public final long b;
    public final int c;
    public final Matrix d;

    public C0154f(v0 v0Var, long j, int i, Matrix matrix) {
        if (v0Var == null) {
            throw new NullPointerException("Null tagBundle");
        }
        this.a = v0Var;
        this.b = j;
        this.c = i;
        this.d = matrix;
    }

    @Override // androidx.camera.core.M
    public final long a() {
        return this.b;
    }

    @Override // androidx.camera.core.M
    public final v0 b() {
        return this.a;
    }

    @Override // androidx.camera.core.M
    public final int c() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0154f) {
            C0154f c0154f = (C0154f) obj;
            if (this.a.equals(c0154f.a) && this.b == c0154f.b && this.c == c0154f.c && this.d.equals(c0154f.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (this.a.hashCode() ^ 1000003) * 1000003;
        long j = this.b;
        return ((((iHashCode ^ ((int) ((j >>> 32) ^ j))) * 1000003) ^ this.c) * 1000003) ^ this.d.hashCode();
    }

    public final String toString() {
        return "ImmutableImageInfo{tagBundle=" + this.a + ", timestamp=" + this.b + ", rotationDegrees=" + this.c + ", sensorToBufferTransformMatrix=" + this.d + "}";
    }
}
