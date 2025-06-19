package androidx.camera.core.impl;

import android.util.Range;
import android.util.Size;
import androidx.camera.core.C0196t;
import java.util.List;

/* renamed from: androidx.camera.core.impl.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0158a {
    public final C0169h a;
    public final int b;
    public final Size c;
    public final C0196t d;
    public final List e;
    public final androidx.camera.camera2.impl.b f;
    public final Range g;

    public C0158a(C0169h c0169h, int i, Size size, C0196t c0196t, List list, androidx.camera.camera2.impl.b bVar, Range range) {
        if (c0169h == null) {
            throw new NullPointerException("Null surfaceConfig");
        }
        this.a = c0169h;
        this.b = i;
        if (size == null) {
            throw new NullPointerException("Null size");
        }
        this.c = size;
        if (c0196t == null) {
            throw new NullPointerException("Null dynamicRange");
        }
        this.d = c0196t;
        if (list == null) {
            throw new NullPointerException("Null captureTypes");
        }
        this.e = list;
        this.f = bVar;
        this.g = range;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0158a)) {
            return false;
        }
        C0158a c0158a = (C0158a) obj;
        if (!this.a.equals(c0158a.a) || this.b != c0158a.b || !this.c.equals(c0158a.c) || !this.d.equals(c0158a.d) || !this.e.equals(c0158a.e)) {
            return false;
        }
        androidx.camera.camera2.impl.b bVar = c0158a.f;
        androidx.camera.camera2.impl.b bVar2 = this.f;
        if (bVar2 == null) {
            if (bVar != null) {
                return false;
            }
        } else if (!bVar2.equals(bVar)) {
            return false;
        }
        Range range = c0158a.g;
        Range range2 = this.g;
        return range2 == null ? range == null : range2.equals(range);
    }

    public final int hashCode() {
        int iHashCode = (((((((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d.hashCode()) * 1000003) ^ this.e.hashCode()) * 1000003;
        androidx.camera.camera2.impl.b bVar = this.f;
        int iHashCode2 = (iHashCode ^ (bVar == null ? 0 : bVar.hashCode())) * 1000003;
        Range range = this.g;
        return iHashCode2 ^ (range != null ? range.hashCode() : 0);
    }

    public final String toString() {
        return "AttachedSurfaceInfo{surfaceConfig=" + this.a + ", imageFormat=" + this.b + ", size=" + this.c + ", dynamicRange=" + this.d + ", captureTypes=" + this.e + ", implementationOptions=" + this.f + ", targetFrameRate=" + this.g + "}";
    }
}
