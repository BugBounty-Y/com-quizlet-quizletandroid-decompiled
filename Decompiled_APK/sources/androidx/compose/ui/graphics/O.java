package androidx.compose.ui.graphics;

import android.graphics.Path;
import android.graphics.RectF;
import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public interface O {
    static void a(O o, androidx.compose.ui.geometry.c cVar) {
        Path.Direction direction;
        C0850j c0850j = (C0850j) o;
        float f = cVar.a;
        if (!Float.isNaN(f)) {
            float f2 = cVar.b;
            if (!Float.isNaN(f2)) {
                float f3 = cVar.c;
                if (!Float.isNaN(f3)) {
                    float f4 = cVar.d;
                    if (!Float.isNaN(f4)) {
                        if (c0850j.b == null) {
                            c0850j.b = new RectF();
                        }
                        RectF rectF = c0850j.b;
                        Intrinsics.d(rectF);
                        rectF.set(f, f2, f3, f4);
                        RectF rectF2 = c0850j.b;
                        Intrinsics.d(rectF2);
                        int iK = AbstractC0147y.k(1);
                        if (iK == 0) {
                            direction = Path.Direction.CCW;
                        } else {
                            if (iK != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            direction = Path.Direction.CW;
                        }
                        c0850j.a.addRect(rectF2, direction);
                        return;
                    }
                }
            }
        }
        throw new IllegalStateException("Invalid rectangle, make sure no value is NaN");
    }

    static void b(O o, androidx.compose.ui.geometry.d dVar) {
        Path.Direction direction;
        C0850j c0850j = (C0850j) o;
        if (c0850j.b == null) {
            c0850j.b = new RectF();
        }
        RectF rectF = c0850j.b;
        Intrinsics.d(rectF);
        float f = dVar.d;
        rectF.set(dVar.a, dVar.b, dVar.c, f);
        if (c0850j.c == null) {
            c0850j.c = new float[8];
        }
        float[] fArr = c0850j.c;
        Intrinsics.d(fArr);
        long j = dVar.e;
        fArr[0] = androidx.compose.ui.geometry.a.b(j);
        fArr[1] = androidx.compose.ui.geometry.a.c(j);
        long j2 = dVar.f;
        fArr[2] = androidx.compose.ui.geometry.a.b(j2);
        fArr[3] = androidx.compose.ui.geometry.a.c(j2);
        long j3 = dVar.g;
        fArr[4] = androidx.compose.ui.geometry.a.b(j3);
        fArr[5] = androidx.compose.ui.geometry.a.c(j3);
        long j4 = dVar.h;
        fArr[6] = androidx.compose.ui.geometry.a.b(j4);
        fArr[7] = androidx.compose.ui.geometry.a.c(j4);
        RectF rectF2 = c0850j.b;
        Intrinsics.d(rectF2);
        float[] fArr2 = c0850j.c;
        Intrinsics.d(fArr2);
        int iK = AbstractC0147y.k(1);
        if (iK == 0) {
            direction = Path.Direction.CCW;
        } else {
            if (iK != 1) {
                throw new NoWhenBranchMatchedException();
            }
            direction = Path.Direction.CW;
        }
        c0850j.a.addRoundRect(rectF2, fArr2, direction);
    }
}
