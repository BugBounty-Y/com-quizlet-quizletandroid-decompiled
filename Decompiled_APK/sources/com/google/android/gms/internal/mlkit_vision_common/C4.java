package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.quizlet.studiablemodels.StudiableRoundProgress;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C4 {
    /* JADX WARN: Removed duplicated region for block: B:30:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:32:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r10, androidx.compose.runtime.InterfaceC0806l r11, androidx.compose.ui.q r12, com.quizlet.learn.ui.toolbar.j r13, kotlin.jvm.functions.Function0 r14, kotlin.jvm.functions.Function0 r15) {
        /*
            java.lang.String r0 = "state"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r0)
            java.lang.String r0 = "onBackClick"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r14, r0)
            java.lang.String r0 = "onSettingsClick"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r15, r0)
            r2 = r11
            androidx.compose.runtime.p r2 = (androidx.compose.runtime.C0814p) r2
            r11 = -796163513(0xffffffffd08b8247, float:-1.8724567E10)
            r2.Z(r11)
            boolean r11 = r2.f(r13)
            if (r11 == 0) goto L20
            r11 = 4
            goto L21
        L20:
            r11 = 2
        L21:
            r11 = r11 | r10
            boolean r0 = r2.h(r14)
            if (r0 == 0) goto L2b
            r0 = 32
            goto L2d
        L2b:
            r0 = 16
        L2d:
            r11 = r11 | r0
            boolean r0 = r2.h(r15)
            if (r0 == 0) goto L37
            r0 = 256(0x100, float:3.59E-43)
            goto L39
        L37:
            r0 = 128(0x80, float:1.8E-43)
        L39:
            r11 = r11 | r0
            boolean r0 = r2.f(r12)
            if (r0 == 0) goto L43
            r0 = 2048(0x800, float:2.87E-42)
            goto L45
        L43:
            r0 = 1024(0x400, float:1.435E-42)
        L45:
            r11 = r11 | r0
            r0 = r11 & 1171(0x493, float:1.641E-42)
            r1 = 1170(0x492, float:1.64E-42)
            if (r0 != r1) goto L5b
            boolean r0 = r2.x()
            if (r0 != 0) goto L53
            goto L5b
        L53:
            r2.Q()
        L56:
            r3 = r12
            r4 = r13
            r5 = r14
            r6 = r15
            goto L76
        L5b:
            boolean r0 = r13 instanceof com.quizlet.learn.ui.toolbar.h
            if (r0 != 0) goto L56
            r0 = r11 & 14
            int r1 = r11 >> 6
            r1 = r1 & 112(0x70, float:1.57E-43)
            r0 = r0 | r1
            int r11 = r11 << 3
            r1 = r11 & 896(0x380, float:1.256E-42)
            r0 = r0 | r1
            r11 = r11 & 7168(0x1c00, float:1.0045E-41)
            r1 = r0 | r11
            r3 = r12
            r4 = r13
            r5 = r14
            r6 = r15
            c(r1, r2, r3, r4, r5, r6)
        L76:
            androidx.compose.runtime.o0 r11 = r2.r()
            if (r11 == 0) goto L87
            r7 = r3
            com.features.flashcards.creatormarketing.i r3 = new com.features.flashcards.creatormarketing.i
            r9 = 29
            r8 = r10
            r3.<init>(r4, r5, r6, r7, r8, r9)
            r11.d = r3
        L87:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.C4.a(int, androidx.compose.runtime.l, androidx.compose.ui.q, com.quizlet.learn.ui.toolbar.j, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0):void");
    }

    public static final void b(com.quizlet.learn.ui.toolbar.d dVar, com.google.firebase.crashlytics.internal.common.i iVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-521002659);
        int i2 = (c0814p.f(dVar) ? 4 : 2) | i | (c0814p.h(iVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z = dVar instanceof com.quizlet.learn.ui.toolbar.a;
            Object obj = C0804k.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(-1276938593);
                c0814p.X(-1565212505);
                Object objI = c0814p.I();
                if (objI == obj) {
                    objI = C0776c.w(((com.quizlet.learn.ui.toolbar.a) dVar).a != null ? (int) ((r3.a / r3.b) * 100) : 0);
                    c0814p.i0(objI);
                }
                androidx.compose.runtime.H0 h0 = (androidx.compose.runtime.H0) objI;
                c0814p.p(false);
                float fI = h0.i() / 100.0f;
                c0814p.X(-1565204101);
                boolean zH = c0814p.h(iVar);
                Object objI2 = c0814p.I();
                if (zH || objI2 == obj) {
                    objI2 = new com.quizlet.features.folders.composables.J(iVar, 20);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                androidx.compose.runtime.W0 w0B = AbstractC0248j.b(fI, null, "oldProgress", (Function1) objI2, c0814p, 3072, 6);
                StudiableRoundProgress studiableRoundProgress = ((com.quizlet.learn.ui.toolbar.a) dVar).a;
                c0814p.X(-1565200045);
                boolean zH2 = ((i2 & 14) == 4) | c0814p.h(iVar);
                Object objI3 = c0814p.I();
                if (zH2 || objI3 == obj) {
                    objI3 = new com.quizlet.learn.ui.toolbar.e(dVar, iVar, h0, null);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                C0776c.g(studiableRoundProgress, iVar, (Function2) objI3, c0814p);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                long j = ((com.quizlet.themes.b) c0814p.j(b)).p0;
                long j2 = ((com.quizlet.themes.b) c0814p.j(b)).q0;
                float f = 0;
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), "learn_toolbar_classic_progress_bar");
                c0814p.X(-1565185358);
                boolean zF = c0814p.f(w0B);
                Object objI4 = c0814p.I();
                if (zF || objI4 == obj) {
                    objI4 = new com.quizlet.learn.ui.progress.a(w0B, 2);
                    c0814p.i0(objI4);
                }
                Function0 function0 = (Function0) objI4;
                Object objG = com.google.android.gms.measurement.internal.Z.g(-1565176321, c0814p, false);
                if (objG == obj) {
                    objG = new com.quizlet.features.universaluploadflow.flashcards.d(9);
                    c0814p.i0(objG);
                }
                c0814p.p(false);
                AbstractC0666j3.b(function0, qVarG, j, j2, 0, f, (Function1) objG, c0814p, 1769520, 0);
                c0814p = c0814p;
                c0814p.p(false);
            } else if (dVar instanceof com.quizlet.learn.ui.toolbar.c) {
                c0814p.X(-1275599207);
                com.quizlet.learn.ui.progress.g gVar = ((com.quizlet.learn.ui.toolbar.c) dVar).a;
                com.quizlet.learn.ui.progress.f fVar = com.quizlet.learn.ui.progress.f.a;
                com.quizlet.themes.m.g.s();
                androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h);
                c0814p.X(-1565160453);
                boolean zH3 = c0814p.h(iVar);
                Object objI5 = c0814p.I();
                if (zH3 || objI5 == obj) {
                    objI5 = new com.quizlet.featuregate.growthbook.a(iVar, 23);
                    c0814p.i0(objI5);
                }
                c0814p.p(false);
                B4.b(gVar, fVar, (Function0) objI5, qVarU, c0814p, 48);
                c0814p.p(false);
            } else {
                if (!(dVar instanceof com.quizlet.learn.ui.toolbar.b)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1565213975, c0814p, false);
                }
                c0814p.X(-1275210498);
                c0814p.p(false);
                if (iVar != null) {
                    iVar.run();
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(dVar, iVar, i, 15);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, com.quizlet.learn.ui.toolbar.j jVar, Function0 function0, Function0 function02) {
        int i2;
        C0814p c0814p;
        boolean z;
        int i3 = 6;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-277074370);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(jVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function02) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "learn_toolbar_content");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            float f = androidx.compose.material3.W4.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.D.a(androidx.compose.runtime.internal.e.e(178777283, new com.quizlet.assembly.compose.cards.c(jVar, 26), c0814p2), null, androidx.compose.runtime.internal.e.e(-675762175, new com.quizlet.explanations.questiondetail.ui.composables.m(22, function0), c0814p2), androidx.compose.runtime.internal.e.e(-1642019080, new com.quizlet.features.questiontypes.mcq.ui.c(i3, jVar, function02), c0814p2), DefinitionKt.NO_Float_VALUE, null, androidx.compose.material3.W4.c(((com.quizlet.themes.b) c0814p2.j(b)).b.g(), 0L, ((com.quizlet.themes.b) c0814p2.j(b)).k, ((com.quizlet.themes.b) c0814p2.j(b)).b.e(), c0814p2, 18), c0814p2, 3462, 178);
            c0814p = c0814p2;
            c0814p.X(-132562228);
            if (jVar instanceof com.quizlet.learn.ui.toolbar.g) {
                com.quizlet.learn.ui.toolbar.g gVar = (com.quizlet.learn.ui.toolbar.g) jVar;
                z = false;
                b(gVar.b, gVar.c, c0814p, 0);
            } else {
                z = false;
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(jVar, qVar, function0, function02, i, 26);
        }
    }

    public static final void d(com.quizlet.learn.ui.toolbar.j jVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2120467286);
        int i2 = (c0814p.f(jVar) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else if ((jVar instanceof com.quizlet.learn.ui.toolbar.i) && ((com.quizlet.learn.ui.toolbar.i) jVar).b != null) {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p.j(b)).p0;
            long j2 = ((com.quizlet.themes.b) c0814p.j(b)).q0;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), "learn_toolbar_header_progress_bar");
            c0814p.X(-907659538);
            boolean z = (i2 & 14) == 4;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.featuregate.growthbook.a(jVar, 24);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC0666j3.b((Function0) objI, qVarG, j, j2, 0, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, ContentType.LONG_FORM_ON_DEMAND);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(jVar, i, 2);
        }
    }

    public static SharedPreferences e(Context context) {
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        return context.getSharedPreferences("com.google.firebase.messaging", 0);
    }

    public static void f(Context context, com.google.firebase.messaging.m mVar, boolean z) {
        com.google.android.gms.tasks.m mVarH;
        int i;
        if (Build.VERSION.SDK_INT >= 29) {
            SharedPreferences sharedPreferencesE = e(context);
            if (sharedPreferencesE.contains("proxy_retention") && sharedPreferencesE.getBoolean("proxy_retention", false) == z) {
                return;
            }
            com.google.android.gms.cloudmessaging.a aVar = mVar.c;
            if (aVar.c.a() >= 241100000) {
                Bundle bundle = new Bundle();
                bundle.putBoolean("proxy_retention", z);
                com.google.android.gms.cloudmessaging.k kVarP = com.google.android.gms.cloudmessaging.k.p(aVar.b);
                synchronized (kVarP) {
                    i = kVarP.b;
                    kVarP.b = i + 1;
                }
                mVarH = kVarP.q(new com.google.android.gms.cloudmessaging.j(i, 4, bundle, 0));
            } else {
                mVarH = S3.h(new IOException("SERVICE_NOT_AVAILABLE"));
            }
            mVarH.d(new androidx.arch.core.executor.a(1), new com.google.firebase.messaging.s(context, z));
        }
    }
}
