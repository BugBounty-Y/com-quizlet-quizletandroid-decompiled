package androidx.glance.appwidget;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public final class K0 {
    public final int a;
    public final int b;

    public K0(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof K0)) {
            return false;
        }
        K0 k0 = (K0) obj;
        return this.a == k0.a && this.b == k0.b;
    }

    public final int hashCode() {
        return AbstractC0147y.k(this.b) + (AbstractC0147y.k(this.a) * 31);
    }

    public final String toString() {
        return "SizeSelector(width=" + androidx.compose.ui.node.B.x(this.a) + ", height=" + androidx.compose.ui.node.B.x(this.b) + ')';
    }
}
