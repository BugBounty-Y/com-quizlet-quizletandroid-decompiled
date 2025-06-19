package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Looper;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E {
    /* JADX WARN: Removed duplicated region for block: B:22:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:24:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.lang.String r22, androidx.compose.ui.q r23, androidx.compose.runtime.InterfaceC0806l r24, int r25) {
        /*
            r0 = r22
            r1 = r23
            r2 = r24
            androidx.compose.runtime.p r2 = (androidx.compose.runtime.C0814p) r2
            r3 = 1727493203(0x66f77453, float:5.8428516E23)
            r2.Z(r3)
            boolean r3 = r2.f(r0)
            if (r3 == 0) goto L16
            r3 = 4
            goto L17
        L16:
            r3 = 2
        L17:
            r3 = r25 | r3
            boolean r4 = r2.f(r1)
            if (r4 == 0) goto L22
            r4 = 32
            goto L24
        L22:
            r4 = 16
        L24:
            r3 = r3 | r4
            r3 = r3 & 19
            r4 = 18
            if (r3 != r4) goto L38
            boolean r3 = r2.x()
            if (r3 != 0) goto L32
            goto L38
        L32:
            r2.Q()
        L35:
            r18 = r2
            goto L98
        L38:
            if (r0 != 0) goto L3b
            goto L35
        L3b:
            androidx.compose.runtime.B r3 = com.quizlet.themes.g.a
            java.lang.Object r4 = r2.j(r3)
            com.quizlet.themes.b r4 = (com.quizlet.themes.b) r4
            com.quizlet.ui.resources.designsystem.generated.d r4 = r4.c
            r4.getClass()
            long r4 = com.quizlet.ui.resources.designsystem.generated.d.S
            androidx.compose.runtime.B r6 = com.quizlet.themes.w.a
            java.lang.Object r6 = r2.j(r6)
            com.quizlet.themes.f r6 = (com.quizlet.themes.f) r6
            androidx.compose.ui.text.L r6 = r6.p
            java.lang.Object r3 = r2.j(r3)
            com.quizlet.themes.b r3 = (com.quizlet.themes.b) r3
            long r7 = r3.K0
            com.quizlet.themes.m r3 = com.quizlet.themes.m.g
            r3.d()
            float r9 = com.quizlet.ui.resources.designsystem.generated.f.g
            androidx.compose.foundation.shape.d r9 = androidx.compose.foundation.shape.e.a(r9)
            androidx.compose.ui.q r7 = androidx.compose.foundation.AbstractC0460p.f(r1, r7, r9)
            r3.s()
            float r3 = com.quizlet.ui.resources.designsystem.generated.j.h
            androidx.compose.ui.q r3 = androidx.compose.foundation.layout.AbstractC0382e.u(r7, r3)
            java.lang.String r7 = "error_container"
            androidx.compose.ui.q r3 = androidx.compose.ui.platform.N.G(r3, r7)
            r16 = 0
            r19 = 0
            r18 = r2
            r1 = r3
            r2 = r4
            r4 = 0
            r17 = r6
            r6 = 0
            r7 = 0
            r9 = 0
            r10 = 0
            r12 = 0
            r13 = 0
            r14 = 0
            r15 = 0
            r20 = 0
            r21 = 65528(0xfff8, float:9.1824E-41)
            androidx.compose.material3.Q4.b(r0, r1, r2, r4, r6, r7, r9, r10, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21)
        L98:
            androidx.compose.runtime.o0 r1 = r18.r()
            if (r1 == 0) goto Laa
            com.quizlet.features.achievements.ui.composables.a r2 = new com.quizlet.features.achievements.ui.composables.a
            r3 = 5
            r4 = r23
            r5 = r25
            r2.<init>(r0, r4, r5, r3)
            r1.d = r2
        Laa:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.E.a(java.lang.String, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final boolean b(io.reactivex.rxjava3.core.l observer) {
        Intrinsics.f(observer, "observer");
        if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
            return true;
        }
        observer.a(new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0));
        StringBuilder sb = new StringBuilder("Expected to be called on the main thread but was ");
        Thread threadCurrentThread = Thread.currentThread();
        Intrinsics.c(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        observer.onError(new IllegalStateException(sb.toString()));
        return false;
    }
}
