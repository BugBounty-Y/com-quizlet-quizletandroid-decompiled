package androidx.camera.core;

import android.util.Size;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import com.amazon.device.ads.DtbConstants;

/* renamed from: androidx.camera.core.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0201y {
    public static final androidx.camera.core.impl.M a;

    static {
        Object size = new Size(640, DtbConstants.DEFAULT_PLAYER_HEIGHT);
        C0196t c0196t = C0196t.d;
        androidx.camera.core.resolutionselector.a aVar = androidx.camera.core.resolutionselector.a.a;
        Size size2 = androidx.camera.core.internal.utils.a.b;
        androidx.camera.core.resolutionselector.c cVar = new androidx.camera.core.resolutionselector.c();
        cVar.a = size2;
        cVar.b = 1;
        Object bVar = new androidx.camera.core.resolutionselector.b(aVar, cVar);
        androidx.camera.camera2.impl.a aVar2 = new androidx.camera.camera2.impl.a(1);
        C0162c c0162c = androidx.camera.core.impl.P.i0;
        androidx.camera.core.impl.X x = aVar2.b;
        x.m(c0162c, size);
        x.m(A0.r0, 1);
        x.m(androidx.camera.core.impl.P.d0, 0);
        x.m(androidx.camera.core.impl.P.l0, bVar);
        if (!c0196t.equals(c0196t)) {
            throw new UnsupportedOperationException("ImageAnalysis currently only supports SDR");
        }
        x.m(androidx.camera.core.impl.O.c0, c0196t);
        a = new androidx.camera.core.impl.M(C0163c0.a(x));
    }
}
