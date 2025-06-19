package androidx.interpolator.view.animation;

import android.view.animation.Interpolator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class b implements Interpolator {
    public final float[] a;
    public final float b;

    public b(float[] fArr) {
        this.a = fArr;
        this.b = 1.0f / (fArr.length - 1);
    }

    @Override // android.animation.TimeInterpolator
    public final float getInterpolation(float f) {
        if (f >= 1.0f) {
            return 1.0f;
        }
        if (f <= DefinitionKt.NO_Float_VALUE) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float[] fArr = this.a;
        int iMin = Math.min((int) ((fArr.length - 1) * f), fArr.length - 2);
        float f2 = this.b;
        float f3 = (f - (iMin * f2)) / f2;
        float f4 = fArr[iMin];
        return android.support.v4.media.session.a.a(fArr[iMin + 1], f4, f3, f4);
    }
}
