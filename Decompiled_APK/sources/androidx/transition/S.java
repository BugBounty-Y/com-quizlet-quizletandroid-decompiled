package androidx.transition;

import android.graphics.Matrix;
import android.view.View;

/* loaded from: classes.dex */
public final class S extends Q {
    @Override // com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2
    public final float a(View view) {
        return view.getTransitionAlpha();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2
    public final void c(View view, float f) {
        view.setTransitionAlpha(f);
    }

    @Override // androidx.transition.Q, com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2
    public final void d(View view, int i) {
        view.setTransitionVisibility(i);
    }

    @Override // androidx.transition.Q
    public final void e(View view, int i, int i2, int i3, int i4) {
        view.setLeftTopRightBottom(i, i2, i3, i4);
    }

    @Override // androidx.transition.Q
    public final void f(View view, Matrix matrix) {
        view.transformMatrixToGlobal(matrix);
    }

    @Override // androidx.transition.Q
    public final void g(View view, Matrix matrix) {
        view.transformMatrixToLocal(matrix);
    }
}
