package androidx.camera.core;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: androidx.camera.core.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0152d {
    public final int a;
    public final C0153e b;

    public C0152d(int i, C0153e c0153e) {
        if (i == 0) {
            throw new NullPointerException("Null type");
        }
        this.a = i;
        this.b = c0153e;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0152d)) {
            return false;
        }
        C0152d c0152d = (C0152d) obj;
        if (!AbstractC0147y.a(this.a, c0152d.a)) {
            return false;
        }
        C0153e c0153e = c0152d.b;
        C0153e c0153e2 = this.b;
        return c0153e2 == null ? c0153e == null : c0153e2.equals(c0153e);
    }

    public final int hashCode() {
        int iK = (AbstractC0147y.k(this.a) ^ 1000003) * 1000003;
        C0153e c0153e = this.b;
        return iK ^ (c0153e == null ? 0 : c0153e.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CameraState{type=");
        int i = this.a;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "CLOSED" : "CLOSING" : "OPEN" : "OPENING" : "PENDING_OPEN");
        sb.append(", error=");
        sb.append(this.b);
        sb.append("}");
        return sb.toString();
    }
}
