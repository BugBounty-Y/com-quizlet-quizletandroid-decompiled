package androidx.constraintlayout.motion.widget;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class j {
    public final View b;
    public final int c;
    public AbstractC3107b6[] j;
    public androidx.constraintlayout.core.motion.utils.b k;
    public int[] o;
    public double[] p;
    public double[] q;
    public String[] r;
    public int[] s;
    public HashMap w;
    public HashMap x;
    public HashMap y;
    public g[] z;
    public final Rect a = new Rect();
    public boolean d = false;
    public int e = -1;
    public final s f = new s();
    public final s g = new s();
    public final h h = new h();
    public final h i = new h();
    public float l = Float.NaN;
    public float m = DefinitionKt.NO_Float_VALUE;
    public float n = 1.0f;
    public final float[] t = new float[4];
    public final ArrayList u = new ArrayList();
    public final ArrayList v = new ArrayList();
    public int A = -1;
    public int B = -1;
    public View C = null;
    public int D = -1;
    public float E = Float.NaN;
    public Interpolator F = null;
    public final boolean G = false;

    public j(View view) {
        this.b = view;
        this.c = view.getId();
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams instanceof androidx.constraintlayout.widget.e) {
            ((androidx.constraintlayout.widget.e) layoutParams).getClass();
        }
    }

    public static void c(Rect rect, Rect rect2, int i, int i2, int i3) {
        if (i == 1) {
            int i4 = rect.left + rect.right;
            rect2.left = ((rect.top + rect.bottom) - rect.width()) / 2;
            rect2.top = i3 - ((rect.height() + i4) / 2);
            rect2.right = rect.width() + rect2.left;
            rect2.bottom = rect.height() + rect2.top;
            return;
        }
        if (i == 2) {
            int i5 = rect.left + rect.right;
            rect2.left = i2 - ((rect.width() + (rect.top + rect.bottom)) / 2);
            rect2.top = (i5 - rect.height()) / 2;
            rect2.right = rect.width() + rect2.left;
            rect2.bottom = rect.height() + rect2.top;
            return;
        }
        if (i == 3) {
            int i6 = rect.left + rect.right;
            rect2.left = ((rect.height() / 2) + rect.top) - (i6 / 2);
            rect2.top = i3 - ((rect.height() + i6) / 2);
            rect2.right = rect.width() + rect2.left;
            rect2.bottom = rect.height() + rect2.top;
            return;
        }
        if (i != 4) {
            return;
        }
        int i7 = rect.left + rect.right;
        rect2.left = i2 - ((rect.width() + (rect.bottom + rect.top)) / 2);
        rect2.top = (i7 - rect.height()) / 2;
        rect2.right = rect.width() + rect2.left;
        rect2.bottom = rect.height() + rect2.top;
    }

    public final void a(double d, float[] fArr, float[] fArr2) {
        float f;
        double[] dArr = new double[4];
        double[] dArr2 = new double[4];
        this.j[0].d(d, dArr);
        this.j[0].f(d, dArr2);
        float f2 = DefinitionKt.NO_Float_VALUE;
        Arrays.fill(fArr2, DefinitionKt.NO_Float_VALUE);
        int[] iArr = this.o;
        s sVar = this.f;
        float f3 = sVar.e;
        float f4 = sVar.f;
        float f5 = sVar.g;
        float f6 = sVar.h;
        float f7 = 0.0f;
        float f8 = 0.0f;
        float f9 = 0.0f;
        for (int i = 0; i < iArr.length; i++) {
            float f10 = (float) dArr[i];
            float f11 = (float) dArr2[i];
            int i2 = iArr[i];
            if (i2 == 1) {
                f3 = f10;
                f2 = f11;
            } else if (i2 == 2) {
                f4 = f10;
                f9 = f11;
            } else if (i2 == 3) {
                f5 = f10;
                f7 = f11;
            } else if (i2 == 4) {
                f6 = f10;
                f8 = f11;
            }
        }
        float f12 = (f7 / 2.0f) + f2;
        float fSin = (f8 / 2.0f) + f9;
        j jVar = sVar.m;
        if (jVar != null) {
            float[] fArr3 = new float[2];
            float[] fArr4 = new float[2];
            jVar.a(d, fArr3, fArr4);
            float f13 = fArr3[0];
            float f14 = fArr3[1];
            float f15 = fArr4[0];
            float f16 = fArr4[1];
            double d2 = f3;
            double d3 = f4;
            float fSin2 = (float) (((Math.sin(d3) * d2) + f13) - (f5 / 2.0f));
            float fCos = (float) ((f14 - (Math.cos(d3) * d2)) - (f6 / 2.0f));
            double d4 = f2;
            f = 2.0f;
            double d5 = f9;
            float fCos2 = (float) ((Math.cos(d3) * d5) + (Math.sin(d3) * d4) + f15);
            fSin = (float) ((Math.sin(d3) * d5) + (f16 - (Math.cos(d3) * d4)));
            f4 = fCos;
            f3 = fSin2;
            f12 = fCos2;
        } else {
            f = 2.0f;
        }
        fArr[0] = (f5 / f) + f3 + DefinitionKt.NO_Float_VALUE;
        fArr[1] = (f6 / f) + f4 + DefinitionKt.NO_Float_VALUE;
        fArr2[0] = f12;
        fArr2[1] = fSin;
    }

    public final void b(s sVar) {
        sVar.c((int) this.b.getX(), (int) this.b.getY(), this.b.getWidth(), this.b.getHeight());
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to find 'out' block for switch in B:334:0x07c0. Please report as an issue. */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:351:0x082a  */
    /* JADX WARN: Removed duplicated region for block: B:353:0x0835  */
    /* JADX WARN: Type inference failed for: r12v54, types: [androidx.constraintlayout.motion.utils.e, androidx.constraintlayout.motion.utils.f] */
    /* JADX WARN: Type inference failed for: r12v60, types: [androidx.constraintlayout.motion.utils.f] */
    /* JADX WARN: Type inference failed for: r15v20 */
    /* JADX WARN: Type inference failed for: r15v21, types: [double[]] */
    /* JADX WARN: Type inference failed for: r15v22 */
    /* JADX WARN: Type inference failed for: r15v25 */
    /* JADX WARN: Type inference failed for: r15v66 */
    /* JADX WARN: Type inference failed for: r1v156, types: [androidx.constraintlayout.motion.utils.m, androidx.constraintlayout.motion.utils.p] */
    /* JADX WARN: Type inference failed for: r4v112, types: [androidx.constraintlayout.motion.utils.o, androidx.constraintlayout.motion.utils.p] */
    /* JADX WARN: Type inference failed for: r4v122, types: [androidx.constraintlayout.motion.utils.p, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v168 */
    /* JADX WARN: Type inference failed for: r4v169 */
    /* JADX WARN: Type inference failed for: r4v74, types: [androidx.constraintlayout.motion.utils.c, androidx.constraintlayout.motion.utils.f] */
    /* JADX WARN: Type inference failed for: r5v101 */
    /* JADX WARN: Type inference failed for: r5v102 */
    /* JADX WARN: Type inference failed for: r5v103 */
    /* JADX WARN: Type inference failed for: r5v104 */
    /* JADX WARN: Type inference failed for: r5v105 */
    /* JADX WARN: Type inference failed for: r5v106 */
    /* JADX WARN: Type inference failed for: r5v107 */
    /* JADX WARN: Type inference failed for: r5v108 */
    /* JADX WARN: Type inference failed for: r5v109 */
    /* JADX WARN: Type inference failed for: r5v110 */
    /* JADX WARN: Type inference failed for: r5v111 */
    /* JADX WARN: Type inference failed for: r5v112 */
    /* JADX WARN: Type inference failed for: r5v113 */
    /* JADX WARN: Type inference failed for: r5v114 */
    /* JADX WARN: Type inference failed for: r5v86 */
    /* JADX WARN: Type inference failed for: r5v88 */
    /* JADX WARN: Type inference failed for: r5v91, types: [androidx.constraintlayout.motion.utils.k, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v93 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(int r50, int r51, long r52) {
        /*
            Method dump skipped, instructions count: 4374
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.widget.j.d(int, int, long):void");
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(" start: x: ");
        s sVar = this.f;
        sb.append(sVar.e);
        sb.append(" y: ");
        sb.append(sVar.f);
        sb.append(" end: x: ");
        s sVar2 = this.g;
        sb.append(sVar2.e);
        sb.append(" y: ");
        sb.append(sVar2.f);
        return sb.toString();
    }
}
