package androidx.camera.core.impl;

import android.util.Size;
import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: androidx.camera.core.impl.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0169h {
    public final int a;
    public final u0 b;
    public final long c;

    public C0169h(int i, u0 u0Var, long j) {
        if (i == 0) {
            throw new NullPointerException("Null configType");
        }
        this.a = i;
        this.b = u0Var;
        this.c = j;
    }

    public static int a(int i) {
        if (i == 35) {
            return 2;
        }
        if (i == 256) {
            return 3;
        }
        if (i == 4101) {
            return 4;
        }
        return i == 32 ? 5 : 1;
    }

    public static C0169h b(int i, int i2, Size size, C0170i c0170i) {
        int iA = a(i2);
        u0 u0Var = u0.NOT_SUPPORT;
        int iA2 = androidx.camera.core.internal.utils.a.a(size);
        if (i == 1) {
            if (iA2 <= androidx.camera.core.internal.utils.a.a((Size) c0170i.b.get(Integer.valueOf(i2)))) {
                u0Var = u0.s720p;
            } else {
                if (iA2 <= androidx.camera.core.internal.utils.a.a((Size) c0170i.d.get(Integer.valueOf(i2)))) {
                    u0Var = u0.s1440p;
                }
            }
        } else if (iA2 <= androidx.camera.core.internal.utils.a.a(c0170i.a)) {
            u0Var = u0.VGA;
        } else if (iA2 <= androidx.camera.core.internal.utils.a.a(c0170i.c)) {
            u0Var = u0.PREVIEW;
        } else if (iA2 <= androidx.camera.core.internal.utils.a.a(c0170i.e)) {
            u0Var = u0.RECORD;
        } else {
            if (iA2 <= androidx.camera.core.internal.utils.a.a((Size) c0170i.f.get(Integer.valueOf(i2)))) {
                u0Var = u0.MAXIMUM;
            } else {
                Size size2 = (Size) c0170i.g.get(Integer.valueOf(i2));
                if (size2 != null) {
                    if (iA2 <= size2.getHeight() * size2.getWidth()) {
                        u0Var = u0.ULTRA_MAXIMUM;
                    }
                }
            }
        }
        return new C0169h(iA, u0Var, 0L);
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0169h)) {
            return false;
        }
        C0169h c0169h = (C0169h) obj;
        return AbstractC0147y.a(this.a, c0169h.a) && this.b.equals(c0169h.b) && this.c == c0169h.c;
    }

    public final int hashCode() {
        int iK = (((AbstractC0147y.k(this.a) ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        long j = this.c;
        return iK ^ ((int) (j ^ (j >>> 32)));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SurfaceConfig{configType=");
        int i = this.a;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "RAW" : "JPEG_R" : "JPEG" : "YUV" : "PRIV");
        sb.append(", configSize=");
        sb.append(this.b);
        sb.append(", streamUseCase=");
        return android.support.v4.media.session.a.g(this.c, "}", sb);
    }
}
