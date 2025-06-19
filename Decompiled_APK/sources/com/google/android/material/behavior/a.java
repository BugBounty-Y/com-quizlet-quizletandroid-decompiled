package com.google.android.material.behavior;

import android.view.View;
import android.view.ViewParent;
import androidx.core.view.V;
import com.airbnb.lottie.network.d;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.material.snackbar.g;
import com.quizlet.data.repository.achievements.h;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class a extends I6 {
    public int a;
    public int b = -1;
    public final /* synthetic */ SwipeDismissBehavior c;

    public a(SwipeDismissBehavior swipeDismissBehavior) {
        this.c = swipeDismissBehavior;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final int b(int i, View view) {
        int width;
        int width2;
        int width3;
        WeakHashMap weakHashMap = V.a;
        boolean z = view.getLayoutDirection() == 1;
        int i2 = this.c.e;
        if (i2 == 0) {
            if (z) {
                width = this.a - view.getWidth();
                width2 = this.a;
            } else {
                width = this.a;
                width3 = view.getWidth();
                width2 = width3 + width;
            }
        } else if (i2 != 1) {
            width = this.a - view.getWidth();
            width2 = view.getWidth() + this.a;
        } else if (z) {
            width = this.a;
            width3 = view.getWidth();
            width2 = width3 + width;
        } else {
            width = this.a - view.getWidth();
            width2 = this.a;
        }
        return Math.min(Math.max(width, i), width2);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final int c(int i, View view) {
        return view.getTop();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final int g(View view) {
        return view.getWidth();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final void i(int i, View view) {
        this.b = i;
        this.a = view.getLeft();
        ViewParent parent = view.getParent();
        if (parent != null) {
            SwipeDismissBehavior swipeDismissBehavior = this.c;
            swipeDismissBehavior.d = true;
            parent.requestDisallowInterceptTouchEvent(true);
            swipeDismissBehavior.d = false;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final void j(int i) {
        d dVar = this.c.b;
        if (dVar != null) {
            g gVar = (g) dVar.b;
            if (i == 0) {
                h.c().i(gVar.u);
            } else if (i == 1 || i == 2) {
                h.c().g(gVar.u);
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final void k(View view, int i, int i2) {
        float width = view.getWidth();
        SwipeDismissBehavior swipeDismissBehavior = this.c;
        float f = width * swipeDismissBehavior.f;
        float width2 = view.getWidth() * swipeDismissBehavior.g;
        float fAbs = Math.abs(i - this.a);
        if (fAbs <= f) {
            view.setAlpha(1.0f);
        } else if (fAbs >= width2) {
            view.setAlpha(DefinitionKt.NO_Float_VALUE);
        } else {
            view.setAlpha(Math.min(Math.max(DefinitionKt.NO_Float_VALUE, 1.0f - ((fAbs - f) / (width2 - f))), 1.0f));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0066  */
    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(android.view.View r9, float r10, float r11) {
        /*
            r8 = this;
            r11 = -1
            r8.b = r11
            int r11 = r9.getWidth()
            r0 = 0
            int r1 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            com.google.android.material.behavior.SwipeDismissBehavior r2 = r8.c
            r3 = 1
            r4 = 0
            if (r1 == 0) goto L39
            java.util.WeakHashMap r5 = androidx.core.view.V.a
            int r5 = r9.getLayoutDirection()
            if (r5 != r3) goto L1a
            r5 = r3
            goto L1b
        L1a:
            r5 = r4
        L1b:
            int r6 = r2.e
            r7 = 2
            if (r6 != r7) goto L21
            goto L52
        L21:
            if (r6 != 0) goto L2d
            if (r5 == 0) goto L2a
            int r1 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r1 >= 0) goto L66
            goto L52
        L2a:
            if (r1 <= 0) goto L66
            goto L52
        L2d:
            if (r6 != r3) goto L66
            if (r5 == 0) goto L34
            if (r1 <= 0) goto L66
            goto L52
        L34:
            int r1 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r1 >= 0) goto L66
            goto L52
        L39:
            int r1 = r9.getLeft()
            int r5 = r8.a
            int r1 = r1 - r5
            int r5 = r9.getWidth()
            float r5 = (float) r5
            r6 = 1056964608(0x3f000000, float:0.5)
            float r5 = r5 * r6
            int r5 = java.lang.Math.round(r5)
            int r1 = java.lang.Math.abs(r1)
            if (r1 < r5) goto L66
        L52:
            int r10 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r10 < 0) goto L61
            int r10 = r9.getLeft()
            int r0 = r8.a
            if (r10 >= r0) goto L5f
            goto L61
        L5f:
            int r0 = r0 + r11
            goto L69
        L61:
            int r10 = r8.a
            int r0 = r10 - r11
            goto L69
        L66:
            int r0 = r8.a
            r3 = r4
        L69:
            androidx.customview.widget.d r10 = r2.a
            int r11 = r9.getTop()
            boolean r10 = r10.o(r0, r11)
            if (r10 == 0) goto L80
            androidx.camera.camera2.internal.A r10 = new androidx.camera.camera2.internal.A
            r10.<init>(r2, r9, r3)
            java.util.WeakHashMap r11 = androidx.core.view.V.a
            r9.postOnAnimation(r10)
            return
        L80:
            if (r3 == 0) goto L89
            com.airbnb.lottie.network.d r10 = r2.b
            if (r10 == 0) goto L89
            r10.m(r9)
        L89:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.behavior.a.l(android.view.View, float, float):void");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final boolean m(int i, View view) {
        int i2 = this.b;
        return (i2 == -1 || i2 == i) && this.c.w(view);
    }
}
