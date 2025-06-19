package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.ColorFilter;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class W6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f answer, String str, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        long jA;
        C0814p c0814p;
        int i2;
        ColorFilter porterDuffColorFilter;
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(answer, "answer");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1008709822);
        int i3 = i | (c0814p2.h(answer) ? 4 : 2) | (c0814p2.f(str) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            boolean zC = com.bumptech.glide.b.c(answer.a ? 1 : 0);
            StudiableImage studiableImage = answer.c;
            String strA = studiableImage != null ? studiableImage.a() : null;
            c0814p2.X(614189070);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_close_x, c0814p2, 0);
            c0814p2.p(false);
            String strD = AbstractC3106b5.d(c0814p2, R.string.incorrect);
            if (zC) {
                c0814p2.X(552691033);
                c0814p2.X(-863555110);
                bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_check, c0814p2, 0);
                c0814p2.p(false);
                strD = AbstractC3106b5.d(c0814p2, R.string.correct);
                jA = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.l();
                c0814p2.p(false);
            } else {
                c0814p2.X(552856139);
                jA = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.a();
                c0814p2.p(false);
            }
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p2, 48, 5);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), gVar, c0814p2, 48);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
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
            String str2 = strD;
            c0814p = c0814p2;
            if (Build.VERSION.SDK_INT >= 29) {
                i2 = 5;
                porterDuffColorFilter = C0854n.a.a(jA, 5);
            } else {
                i2 = 5;
                porterDuffColorFilter = new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jA), androidx.compose.ui.graphics.F.E(5));
            }
            C0853m c0853m = new C0853m(jA, i2, porterDuffColorFilter);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "feedbackImage");
            mVar.h();
            long j = jA;
            AbstractC0460p.c(bVarA, str2, androidx.compose.foundation.layout.K0.k(qVarG, com.quizlet.ui.resources.designsystem.generated.h.g), null, null, DefinitionKt.NO_Float_VALUE, c0853m, c0814p, 0, 56);
            c0814p.X(-1784188425);
            if (strA == null) {
                z = false;
            } else {
                androidx.compose.ui.q qVarE = androidx.compose.foundation.layout.K0.e(androidx.compose.ui.platform.N.G(nVar, "answerImage"), com.quizlet.themes.m.q, 72);
                c0814p.X(-842870018);
                boolean zH = c0814p.h(xVarH);
                Object objI = c0814p.I();
                if (zH || objI == v) {
                    objI = new com.quizlet.features.folders.changetags.composables.f(xVarH, 17);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarE, false, null, (Function0) objI, 7);
                String str3 = strA;
                z = false;
                com.google.android.gms.internal.mlkit_vision_camera.r3.a(str3, null, qVarL, null, null, null, c0814p, 48, 2040);
                c0814p = c0814p;
                Z5.c(str3, null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
            }
            c0814p.p(z);
            c0814p.X(-1784169852);
            if (str == null) {
                z2 = false;
            } else {
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l;
                c0814p.X(-842857357);
                boolean zH2 = c0814p.h(answer) | ((i3 & 7168) == 2048);
                Object objI2 = c0814p.I();
                if (zH2 || objI2 == v) {
                    objI2 = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(2, answer, function1);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                C0814p c0814p3 = c0814p;
                z2 = false;
                androidx.compose.material3.Q4.b(str, AbstractC0460p.l(nVar, false, null, (Function0) objI2, 7), j, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p3, (i3 >> 3) & 14, 0, 65016);
                c0814p = c0814p3;
            }
            c0814p.p(z2);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(answer, str, qVar, function1, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0185  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x018b  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0195  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final com.google.android.gms.internal.mlkit_vision_document_scanner.e7 r20, androidx.compose.ui.q r21, final kotlin.jvm.functions.Function1 r22, androidx.compose.runtime.InterfaceC0806l r23, int r24) {
        /*
            Method dump skipped, instructions count: 453
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.W6.b(com.google.android.gms.internal.mlkit_vision_document_scanner.e7, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }
}
