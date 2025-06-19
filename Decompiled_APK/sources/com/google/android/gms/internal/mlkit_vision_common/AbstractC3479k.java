package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3479k {
    public static final void a(com.quizlet.features.questiontypes.written.data.c gradingState, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(androidx.compose.foundation.layout.D.a, "<this>");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-254105551);
        if ((((c0814p2.f(gradingState) ? 32 : 16) | i) & 17) == 16 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.n();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, gradingState.b), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.o, 7), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.l(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).j, c0814p, 0, 0, 65528);
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(com.quizlet.features.questiontypes.composables.a.b, androidx.compose.ui.platform.N.G(nVar, "correctAnswer"), gradingState.a, null, null, c0814p, 54, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(gradingState, i, 24);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0049, code lost:
    
        if (com.google.android.gms.internal.mlkit_vision_camera.s3.b(r0.getWidth(), r0.getHeight(), (int) (r4 >> 32), (int) (r4 & 4294967295L), r11) == 1.0d) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Bitmap b(android.graphics.drawable.Drawable r8, android.graphics.Bitmap.Config r9, coil3.size.h r10, coil3.size.g r11, boolean r12) {
        /*
            boolean r0 = r8 instanceof android.graphics.drawable.BitmapDrawable
            r1 = 4294967295(0xffffffff, double:2.1219957905E-314)
            r3 = 32
            if (r0 == 0) goto L4c
            r0 = r8
            android.graphics.drawable.BitmapDrawable r0 = (android.graphics.drawable.BitmapDrawable) r0
            android.graphics.Bitmap r0 = r0.getBitmap()
            android.graphics.Bitmap$Config r4 = r0.getConfig()
            if (r9 == 0) goto L1f
            android.graphics.Bitmap$Config r5 = android.graphics.Bitmap.Config.HARDWARE
            if (r9 != r5) goto L1d
            goto L1f
        L1d:
            r5 = r9
            goto L21
        L1f:
            android.graphics.Bitmap$Config r5 = android.graphics.Bitmap.Config.ARGB_8888
        L21:
            if (r4 != r5) goto L4c
            if (r12 == 0) goto L26
            goto L4b
        L26:
            int r12 = r0.getWidth()
            int r4 = r0.getHeight()
            coil3.size.h r5 = coil3.size.h.c
            long r4 = com.google.android.gms.internal.mlkit_vision_camera.s3.a(r12, r4, r10, r11, r5)
            long r6 = r4 >> r3
            int r12 = (int) r6
            long r4 = r4 & r1
            int r4 = (int) r4
            int r5 = r0.getWidth()
            int r6 = r0.getHeight()
            double r4 = com.google.android.gms.internal.mlkit_vision_camera.s3.b(r5, r6, r12, r4, r11)
            r6 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            int r12 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r12 != 0) goto L4c
        L4b:
            return r0
        L4c:
            android.graphics.drawable.Drawable r8 = r8.mutate()
            int r12 = coil3.util.l.b(r8)
            r0 = 512(0x200, float:7.17E-43)
            if (r12 <= 0) goto L59
            goto L5a
        L59:
            r12 = r0
        L5a:
            int r4 = coil3.util.l.a(r8)
            if (r4 <= 0) goto L61
            r0 = r4
        L61:
            coil3.size.h r4 = coil3.size.h.c
            long r4 = com.google.android.gms.internal.mlkit_vision_camera.s3.a(r12, r0, r10, r11, r4)
            long r6 = r4 >> r3
            int r10 = (int) r6
            long r1 = r1 & r4
            int r1 = (int) r1
            double r10 = com.google.android.gms.internal.mlkit_vision_camera.s3.b(r12, r0, r10, r1, r11)
            double r1 = (double) r12
            double r1 = r1 * r10
            int r12 = kotlin.math.c.a(r1)
            double r0 = (double) r0
            double r10 = r10 * r0
            int r10 = kotlin.math.c.a(r10)
            if (r9 == 0) goto L82
            android.graphics.Bitmap$Config r11 = android.graphics.Bitmap.Config.HARDWARE
            if (r9 != r11) goto L84
        L82:
            android.graphics.Bitmap$Config r9 = android.graphics.Bitmap.Config.ARGB_8888
        L84:
            android.graphics.Bitmap r9 = android.graphics.Bitmap.createBitmap(r12, r10, r9)
            android.graphics.Rect r11 = r8.getBounds()
            int r0 = r11.left
            int r1 = r11.top
            int r2 = r11.right
            int r11 = r11.bottom
            r3 = 0
            r8.setBounds(r3, r3, r12, r10)
            android.graphics.Canvas r10 = new android.graphics.Canvas
            r10.<init>(r9)
            r8.draw(r10)
            r8.setBounds(r0, r1, r2, r11)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3479k.b(android.graphics.drawable.Drawable, android.graphics.Bitmap$Config, coil3.size.h, coil3.size.g, boolean):android.graphics.Bitmap");
    }
}
