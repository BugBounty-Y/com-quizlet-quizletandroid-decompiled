package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.p6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3699p6 {
    /* JADX WARN: Removed duplicated region for block: B:15:0x0038  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:39:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r16, int r17, androidx.compose.runtime.InterfaceC0806l r18, androidx.compose.ui.q r19, java.lang.String r20, kotlin.jvm.functions.Function0 r21) {
        /*
            r1 = r19
            r3 = r21
            java.lang.String r0 = "onClick"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            r12 = r18
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            r0 = -1570117091(0xffffffffa269ea1d, float:-3.1701327E-18)
            r12.Z(r0)
            boolean r0 = r12.f(r1)
            if (r0 == 0) goto L1b
            r0 = 4
            goto L1c
        L1b:
            r0 = 2
        L1c:
            r0 = r16 | r0
            r2 = r17 & 2
            if (r2 != 0) goto L2d
            r2 = r20
            boolean r4 = r12.f(r2)
            if (r4 == 0) goto L2f
            r4 = 32
            goto L31
        L2d:
            r2 = r20
        L2f:
            r4 = 16
        L31:
            r0 = r0 | r4
            boolean r4 = r12.h(r3)
            if (r4 == 0) goto L3b
            r4 = 256(0x100, float:3.59E-43)
            goto L3d
        L3b:
            r4 = 128(0x80, float:1.8E-43)
        L3d:
            r0 = r0 | r4
            r4 = r0 & 147(0x93, float:2.06E-43)
            r5 = 146(0x92, float:2.05E-43)
            if (r4 != r5) goto L4f
            boolean r4 = r12.x()
            if (r4 != 0) goto L4b
            goto L4f
        L4b:
            r12.Q()
            goto L93
        L4f:
            r12.S()
            r4 = r16 & 1
            if (r4 == 0) goto L67
            boolean r4 = r12.w()
            if (r4 == 0) goto L5d
            goto L67
        L5d:
            r12.Q()
            r4 = r17 & 2
            if (r4 == 0) goto L73
        L64:
            r0 = r0 & (-113(0xffffffffffffff8f, float:NaN))
            goto L73
        L67:
            r4 = r17 & 2
            if (r4 == 0) goto L73
            r2 = 2132018492(0x7f14053c, float:1.9675292E38)
            java.lang.String r2 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.d(r12, r2)
            goto L64
        L73:
            r12.q()
            r4 = 1065353216(0x3f800000, float:1.0)
            androidx.compose.ui.q r4 = androidx.compose.foundation.layout.K0.c(r1, r4)
            int r5 = r0 >> 3
            r5 = r5 & 14
            r0 = r0 & 896(0x380, float:1.256E-42)
            r13 = r5 | r0
            r10 = 0
            r11 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r9 = 0
            r14 = 1016(0x3f8, float:1.424E-42)
            r15 = r4
            r4 = r3
            r3 = r15
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14)
        L93:
            androidx.compose.runtime.o0 r6 = r12.r()
            if (r6 == 0) goto La6
            com.quizlet.features.notes.detail.composables.common.d r0 = new com.quizlet.features.notes.detail.composables.common.d
            r4 = r16
            r5 = r17
            r3 = r21
            r0.<init>(r1, r2, r3, r4, r5)
            r6.d = r0
        La6:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3699p6.a(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0):void");
    }

    public static final void b(com.quizlet.baseui.base.f fVar, int i) {
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        fVar.getWindow().getDecorView().setBackgroundColor(com.quizlet.themes.extensions.a.a(fVar, i));
    }
}
