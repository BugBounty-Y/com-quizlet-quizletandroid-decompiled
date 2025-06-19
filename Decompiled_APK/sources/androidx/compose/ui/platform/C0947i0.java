package androidx.compose.ui.platform;

import android.graphics.Matrix;
import android.view.View;
import android.view.ViewParent;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0947i0 implements InterfaceC0945h0 {
    public final Matrix a = new Matrix();
    public final int[] b = new int[2];

    @Override // androidx.compose.ui.platform.InterfaceC0945h0
    public void e(@NotNull View view, @NotNull float[] fArr) {
        Matrix matrix = this.a;
        matrix.reset();
        view.transformMatrixToGlobal(matrix);
        ViewParent parent = view.getParent();
        while (parent instanceof View) {
            view = parent;
            parent = view.getParent();
        }
        int[] iArr = this.b;
        view.getLocationOnScreen(iArr);
        int i = iArr[0];
        int i2 = iArr[1];
        view.getLocationInWindow(iArr);
        matrix.postTranslate(iArr[0] - i, iArr[1] - i2);
        androidx.compose.ui.graphics.F.u(matrix, fArr);
    }
}
