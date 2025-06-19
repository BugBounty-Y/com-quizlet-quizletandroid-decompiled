package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3491m {
    public static final void a(com.quizlet.features.questiontypes.written.data.e gradingState, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(androidx.compose.foundation.layout.D.a, "<this>");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2093589940);
        if (((i | (c0814p2.f(gradingState) ? 32 : 16)) & 17) == 16 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.n();
            float f = com.quizlet.ui.resources.designsystem.generated.j.o;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7);
            String strD = AbstractC3106b5.d(c0814p2, gradingState.c);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jA = ((com.quizlet.themes.b) c0814p2.j(b)).b.a();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.b;
            androidx.compose.material3.Q4.b(strD, qVarY, jA, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p2, 0, 0, 65528);
            com.quizlet.features.questiontypes.composables.a aVar = com.quizlet.features.questiontypes.composables.a.c;
            mVar.q();
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(aVar, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 7), "incorrectAnswer"), gradingState.a, null, null, c0814p2, 6, 24);
            mVar.n();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.written_label_correct_answer), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), ((com.quizlet.themes.b) c0814p2.j(b)).b.l(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p, 0, 0, 65528);
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(com.quizlet.features.questiontypes.composables.a.b, androidx.compose.ui.platform.N.G(nVar, "correctAnswer"), gradingState.b, null, null, c0814p, 54, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(gradingState, i, 26);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.lifecycle.C r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            boolean r0 = r7 instanceof coil3.util.f
            if (r0 == 0) goto L13
            r0 = r7
            coil3.util.f r0 = (coil3.util.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            coil3.util.f r0 = new coil3.util.f
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlin.jvm.internal.J r6 = r0.k
            androidx.lifecycle.C r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L2b
            goto L7f
        L2b:
            r7 = move-exception
            goto L8d
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r7 = r6
            androidx.lifecycle.L r7 = (androidx.lifecycle.L) r7
            androidx.lifecycle.B r7 = r7.d
            androidx.lifecycle.B r2 = androidx.lifecycle.B.d
            boolean r7 = r7.a(r2)
            if (r7 == 0) goto L48
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L48:
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            r0.j = r6     // Catch: java.lang.Throwable -> L8b
            r0.k = r7     // Catch: java.lang.Throwable -> L8b
            r0.m = r3     // Catch: java.lang.Throwable -> L8b
            kotlinx.coroutines.l r2 = new kotlinx.coroutines.l     // Catch: java.lang.Throwable -> L8b
            kotlin.coroutines.h r4 = kotlin.coroutines.intrinsics.h.b(r0)     // Catch: java.lang.Throwable -> L8b
            r2.<init>(r3, r4)     // Catch: java.lang.Throwable -> L8b
            r2.r()     // Catch: java.lang.Throwable -> L8b
            coil3.util.g r3 = new coil3.util.g     // Catch: java.lang.Throwable -> L8b
            r3.<init>(r2)     // Catch: java.lang.Throwable -> L8b
            r7.a = r3     // Catch: java.lang.Throwable -> L8b
            r6.a(r3)     // Catch: java.lang.Throwable -> L8b
            java.lang.Object r2 = r2.q()     // Catch: java.lang.Throwable -> L8b
            if (r2 != r1) goto L7a
            java.lang.String r3 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)     // Catch: java.lang.Throwable -> L8b
            goto L7a
        L75:
            r5 = r0
            r0 = r6
            r6 = r7
            r7 = r5
            goto L8d
        L7a:
            if (r2 != r1) goto L7d
            return r1
        L7d:
            r0 = r6
            r6 = r7
        L7f:
            java.lang.Object r6 = r6.a
            androidx.lifecycle.I r6 = (androidx.lifecycle.I) r6
            if (r6 == 0) goto L88
            r0.b(r6)
        L88:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L8b:
            r0 = move-exception
            goto L75
        L8d:
            java.lang.Object r6 = r6.a
            androidx.lifecycle.I r6 = (androidx.lifecycle.I) r6
            if (r6 == 0) goto L96
            r0.b(r6)
        L96:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3491m.b(androidx.lifecycle.C, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
