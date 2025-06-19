package androidx.compose.foundation.lazy.grid;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: androidx.compose.foundation.lazy.grid.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0426a {
    public final int a;

    public C0426a(int i) {
        this.a = i;
        if (i <= 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Provided count ", " should be larger than zero").toString());
        }
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0426a) {
            return this.a == ((C0426a) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return -this.a;
    }
}
