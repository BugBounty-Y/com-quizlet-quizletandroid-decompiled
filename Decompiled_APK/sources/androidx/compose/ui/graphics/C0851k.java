package androidx.compose.ui.graphics;

import android.graphics.PathMeasure;

/* renamed from: androidx.compose.ui.graphics.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0851k {
    public final PathMeasure a;

    public C0851k(PathMeasure pathMeasure) {
        this.a = pathMeasure;
    }

    public final void a(float f, float f2, C0850j c0850j) {
        if (c0850j == null) {
            throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
        }
        this.a.getSegment(f, f2, c0850j.a, true);
    }
}
