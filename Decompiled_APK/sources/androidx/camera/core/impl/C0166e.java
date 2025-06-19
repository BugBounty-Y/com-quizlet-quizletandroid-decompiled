package androidx.camera.core.impl;

import androidx.camera.core.C0196t;
import com.google.android.gms.ads.internal.client.C1608n;
import java.util.Collections;
import java.util.List;

/* renamed from: androidx.camera.core.impl.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0166e {
    public final J a;
    public final List b;
    public final int c;
    public final int d;
    public final C0196t e;

    public C0166e(J j, List list, int i, int i2, C0196t c0196t) {
        this.a = j;
        this.b = list;
        this.c = i;
        this.d = i2;
        this.e = c0196t;
    }

    public static C1608n a(J j) {
        C1608n c1608n = new C1608n();
        if (j == null) {
            throw new NullPointerException("Null surface");
        }
        c1608n.a = j;
        List list = Collections.EMPTY_LIST;
        if (list == null) {
            throw new NullPointerException("Null sharedSurfaces");
        }
        c1608n.b = list;
        c1608n.c = -1;
        c1608n.d = -1;
        c1608n.e = C0196t.d;
        return c1608n;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0166e)) {
            return false;
        }
        C0166e c0166e = (C0166e) obj;
        return this.a.equals(c0166e.a) && this.b.equals(c0166e.b) && this.c == c0166e.c && this.d == c0166e.d && this.e.equals(c0166e.e);
    }

    public final int hashCode() {
        return ((((((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * (-721379959)) ^ this.c) * 1000003) ^ this.d) * 1000003) ^ this.e.hashCode();
    }

    public final String toString() {
        return "OutputConfig{surface=" + this.a + ", sharedSurfaces=" + this.b + ", physicalCameraId=null, mirrorMode=" + this.c + ", surfaceGroupId=" + this.d + ", dynamicRange=" + this.e + "}";
    }
}
