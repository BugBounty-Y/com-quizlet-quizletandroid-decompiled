package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class G {
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(java.lang.String r13, long r14, com.quizlet.shared.cache.c r16, kotlin.coroutines.jvm.internal.c r17) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException, java.io.UnsupportedEncodingException {
        /*
            r0 = r17
            boolean r1 = r0 instanceof com.mayakapps.kache.C4037f
            if (r1 == 0) goto L16
            r1 = r0
            com.mayakapps.kache.f r1 = (com.mayakapps.kache.C4037f) r1
            int r2 = r1.l
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.l = r2
        L14:
            r11 = r1
            goto L1c
        L16:
            com.mayakapps.kache.f r1 = new com.mayakapps.kache.f
            r1.<init>(r0)
            goto L14
        L1c:
            java.lang.Object r0 = r11.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r11.l
            r3 = 1
            if (r2 == 0) goto L36
            if (r2 != r3) goto L2e
            com.mayakapps.kache.c r13 = r11.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L9d
        L2e:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.mayakapps.kache.c r0 = new com.mayakapps.kache.c
            java.lang.String r2 = "directory"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r2)
            r0.<init>()
            com.mayakapps.kache.x r4 = com.mayakapps.kache.x.a
            r0.a = r4
            kotlinx.coroutines.scheduling.d r5 = com.mayakapps.kache.AbstractC4036e.b
            kotlinx.coroutines.internal.d r6 = kotlinx.coroutines.E.c(r5)
            r0.b = r6
            r0.c = r3
            com.mayakapps.kache.K r6 = com.mayakapps.kache.K.a
            r0.d = r6
            r7 = r16
            r7.invoke(r0)
            java.lang.String r7 = okio.x.b
            r7 = 0
            okio.x r13 = com.quizlet.quizletandroid.ui.folder.logging.a.f(r13, r7)
            androidx.credentials.playservices.controllers.BeginSignIn.c r7 = new androidx.credentials.playservices.controllers.BeginSignIn.c
            r8 = 13
            r7.<init>(r0, r8)
            r11.j = r0
            r11.l = r3
            com.mayakapps.kache.A r8 = new com.mayakapps.kache.A
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r2)
            r8.<init>()
            r8.a = r4
            okio.t r2 = com.mayakapps.kache.AbstractC4036e.a
            kotlinx.coroutines.internal.d r4 = kotlinx.coroutines.E.c(r5)
            r8.b = r4
            r8.c = r3
            r8.d = r6
            r7.invoke(r8)
            r3 = r2
            com.quizlet.shared.usecase.folderstudymaterials.d r2 = com.mayakapps.kache.H.j
            com.mayakapps.kache.x r7 = r8.a
            kotlinx.coroutines.internal.d r4 = r8.b
            int r9 = r8.c
            com.mayakapps.kache.K r10 = r8.d
            r5 = r14
            r8 = r4
            r4 = r13
            java.lang.Object r13 = r2.m(r3, r4, r5, r7, r8, r9, r10, r11)
            if (r13 != r1) goto L9a
            return r1
        L9a:
            r12 = r0
            r0 = r13
            r13 = r12
        L9d:
            com.mayakapps.kache.H r0 = (com.mayakapps.kache.H) r0
            com.mayakapps.kache.d r1 = new com.mayakapps.kache.d
            kotlinx.coroutines.internal.d r13 = r13.b
            r1.<init>(r0, r13)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.G.a(java.lang.String, long, com.quizlet.shared.cache.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final void b(com.quizlet.login.authentication.k authenticationError, Function0 onDismiss, Function0 onConfirmClicked, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(authenticationError, "authenticationError");
        Intrinsics.checkNotNullParameter(onDismiss, "onDismiss");
        Intrinsics.checkNotNullParameter(onConfirmClicked, "onConfirmClicked");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(340928450);
        int i2 = i | (c0814p2.h(authenticationError) ? 4 : 2) | (c0814p2.h(onDismiss) ? 32 : 16) | (c0814p2.h(onConfirmClicked) ? 256 : 128) | 3072;
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p = c0814p2;
            androidx.compose.material3.Z1.a(onDismiss, androidx.compose.runtime.internal.e.e(-1008290182, new com.quizlet.assembly.compose.menu.l(authenticationError, context, onConfirmClicked, 26), c0814p2), androidx.compose.ui.platform.N.G(nVar, "loginErrorDialog"), null, androidx.compose.runtime.internal.e.e(1440342262, new com.quizlet.login.common.ui.j(authenticationError, context, 0), c0814p2), androidx.compose.runtime.internal.e.e(-1168725099, new com.quizlet.login.common.ui.j(authenticationError, context, 1), c0814p2), null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, 0L, DefinitionKt.NO_Float_VALUE, null, c0814p, ((i2 >> 3) & 14) | 1769520, 0, 16024);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a((Object) authenticationError, onDismiss, onConfirmClicked, qVar2, i, 1);
        }
    }
}
