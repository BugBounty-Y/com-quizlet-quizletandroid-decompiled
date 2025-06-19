package androidx.camera.core;

import android.graphics.Rect;
import android.util.Size;
import androidx.camera.core.impl.InterfaceC0185y;

/* renamed from: androidx.camera.core.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0155g {
    public final Size a;
    public final Rect b;
    public final InterfaceC0185y c;
    public final int d;
    public final boolean e;

    public C0155g(Size size, Rect rect, InterfaceC0185y interfaceC0185y, int i, boolean z) {
        if (size == null) {
            throw new NullPointerException("Null inputSize");
        }
        this.a = size;
        if (rect == null) {
            throw new NullPointerException("Null inputCropRect");
        }
        this.b = rect;
        this.c = interfaceC0185y;
        this.d = i;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0155g) {
            C0155g c0155g = (C0155g) obj;
            if (this.a.equals(c0155g.a) && this.b.equals(c0155g.b)) {
                InterfaceC0185y interfaceC0185y = c0155g.c;
                InterfaceC0185y interfaceC0185y2 = this.c;
                if (interfaceC0185y2 != null ? interfaceC0185y2.equals(interfaceC0185y) : interfaceC0185y == null) {
                    if (this.d == c0155g.d && this.e == c0155g.e) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        InterfaceC0185y interfaceC0185y = this.c;
        return ((((iHashCode ^ (interfaceC0185y == null ? 0 : interfaceC0185y.hashCode())) * 1000003) ^ this.d) * 1000003) ^ (this.e ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CameraInputInfo{inputSize=");
        sb.append(this.a);
        sb.append(", inputCropRect=");
        sb.append(this.b);
        sb.append(", cameraInternal=");
        sb.append(this.c);
        sb.append(", rotationDegrees=");
        sb.append(this.d);
        sb.append(", mirroring=");
        return android.support.v4.media.session.a.o("}", sb, this.e);
    }
}
