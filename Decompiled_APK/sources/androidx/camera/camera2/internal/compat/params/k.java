package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import java.util.Objects;

/* loaded from: classes.dex */
public final class k {
    public final OutputConfiguration a;
    public long b = 1;

    public k(OutputConfiguration outputConfiguration) {
        this.a = outputConfiguration;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Objects.equals(this.a, kVar.a) && this.b == kVar.b;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() ^ 31;
        return Long.hashCode(this.b) ^ ((iHashCode << 5) - iHashCode);
    }
}
