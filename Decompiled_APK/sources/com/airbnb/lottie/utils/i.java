package com.airbnb.lottie.utils;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PathMeasure;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Closeable;
import java.io.IOException;

/* loaded from: classes.dex */
public abstract class i {
    public static final Matrix a = new Matrix();
    public static final androidx.camera.core.impl.utils.executor.b b = new androidx.camera.core.impl.utils.executor.b(2);
    public static final androidx.camera.core.impl.utils.executor.b c = new androidx.camera.core.impl.utils.executor.b(3);
    public static final androidx.camera.core.impl.utils.executor.b d = new androidx.camera.core.impl.utils.executor.b(4);
    public static final androidx.camera.core.impl.utils.executor.b e = new androidx.camera.core.impl.utils.executor.b(5);
    public static final float f = (float) (Math.sqrt(2.0d) / 2.0d);

    public static void a(Path path, float f2, float f3, float f4) {
        PathMeasure pathMeasure = (PathMeasure) b.get();
        Path path2 = (Path) c.get();
        Path path3 = (Path) d.get();
        pathMeasure.setPath(path, false);
        float length = pathMeasure.getLength();
        if (!(f2 == 1.0f && f3 == DefinitionKt.NO_Float_VALUE) && length >= 1.0f && Math.abs((f3 - f2) - 1.0f) >= 0.01d) {
            float f5 = f2 * length;
            float f6 = f3 * length;
            float f7 = f4 * length;
            float fMin = Math.min(f5, f6) + f7;
            float fMax = Math.max(f5, f6) + f7;
            if (fMin >= length && fMax >= length) {
                fMin = g.d(fMin, length);
                fMax = g.d(fMax, length);
            }
            if (fMin < DefinitionKt.NO_Float_VALUE) {
                fMin = g.d(fMin, length);
            }
            if (fMax < DefinitionKt.NO_Float_VALUE) {
                fMax = g.d(fMax, length);
            }
            if (fMin == fMax) {
                path.reset();
                return;
            }
            if (fMin >= fMax) {
                fMin -= length;
            }
            path2.reset();
            pathMeasure.getSegment(fMin, fMax, path2, true);
            if (fMax > length) {
                path3.reset();
                pathMeasure.getSegment(DefinitionKt.NO_Float_VALUE, fMax % length, path3, true);
                path2.addPath(path3);
            } else if (fMin < DefinitionKt.NO_Float_VALUE) {
                path3.reset();
                pathMeasure.getSegment(fMin + length, length, path3, true);
                path2.addPath(path3);
            }
            path.set(path2);
        }
    }

    public static void b(Closeable closeable) throws IOException {
        try {
            closeable.close();
        } catch (RuntimeException e2) {
            throw e2;
        } catch (Exception unused) {
        }
    }

    public static float c() {
        return Resources.getSystem().getDisplayMetrics().density;
    }

    public static Bitmap d(Bitmap bitmap, int i, int i2) {
        if (bitmap.getWidth() == i && bitmap.getHeight() == i2) {
            return bitmap;
        }
        Bitmap bitmapCreateScaledBitmap = Bitmap.createScaledBitmap(bitmap, i, i2, true);
        bitmap.recycle();
        return bitmapCreateScaledBitmap;
    }
}
