package coil3.util;

import android.os.SystemClock;
import com.comscore.util.log.LogLevel;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes.dex */
public final class h implements d {
    @Override // coil3.util.d
    public final boolean a(coil3.size.h hVar) {
        coil3.size.c cVar = hVar.a;
        boolean z = cVar instanceof coil3.size.a;
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        if ((z ? ((coil3.size.a) cVar).a : Integer.MAX_VALUE) <= 100) {
            return false;
        }
        coil3.size.c cVar2 = hVar.b;
        if (cVar2 instanceof coil3.size.a) {
            i = ((coil3.size.a) cVar2).a;
        }
        return i > 100;
    }

    @Override // coil3.util.d
    public final boolean c() {
        boolean z;
        synchronized (c.a) {
            try {
                int i = c.c;
                c.c = i + 1;
                if (i >= 30 || SystemClock.uptimeMillis() > c.d + LogLevel.NONE) {
                    c.c = 0;
                    c.d = SystemClock.uptimeMillis();
                    String[] list = c.b.list();
                    if (list == null) {
                        list = new String[0];
                    }
                    c.e = list.length < 800;
                }
                z = c.e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return z;
    }
}
