package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.C4447e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T2 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, com.quizlet.features.settings.viewmodels.l lVar, Function0 onSuccess, Function0 function0) {
        C0814p c0814p;
        int i2;
        com.quizlet.features.settings.viewmodels.l lVar2;
        int i3;
        C0814p c0814p2;
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-1379493363);
        int i4 = (c0814p3.h(onSuccess) ? 4 : 2) | i | (c0814p3.h(function0) ? 32 : 16) | 128;
        if ((i4 & 147) == 146 && c0814p3.x()) {
            c0814p3.Q();
            lVar2 = lVar;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            int i5 = i & 1;
            Object obj = C0804k.a;
            if (i5 == 0 || c0814p3.w()) {
                c0814p3.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                c0814p = c0814p3;
                Object objE = AbstractC3417z1.e(C4444b.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i4 & (-897);
                lVar2 = (com.quizlet.features.settings.viewmodels.l) objE;
            } else {
                c0814p3.Q();
                i2 = i4 & (-897);
                lVar2 = lVar;
                c0814p = c0814p3;
            }
            c0814p.q();
            C4444b c4444b = (C4444b) lVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(c4444b.f, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = ((C4447e) lVar2).b;
            c0814p.X(-1808637735);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == obj) {
                objI = new com.quizlet.features.settings.composables.changeuseremail.f(function0, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                i3 = i2;
                objI2 = new com.quizlet.features.settings.composables.changeuseremail.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            } else {
                i3 = i2;
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = c4444b.h;
            c0814p.X(-1808634748);
            boolean z2 = (i3 & 14) == 4;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == obj) {
                objI3 = new com.quizlet.features.settings.composables.changeuseremail.g(onSuccess, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j2) | c0814p.h(d0Var2) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zF || objI4 == obj) {
                objI4 = new com.quizlet.features.settings.composables.changeuseremail.e(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            Object[] objArr = new Object[0];
            c0814p.X(-1808632673);
            Object objI5 = c0814p.I();
            if (objI5 == obj) {
                objI5 = new C4392k(25);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            C0814p c0814p4 = c0814p;
            c0814p2 = c0814p4;
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI5, c0814p4, 3072, 6);
            String str = (String) interfaceC0773a0.getValue();
            com.quizlet.features.settings.data.states.d dVar = (com.quizlet.features.settings.data.states.d) interfaceC0773a0M.getValue();
            c0814p2.X(-1808627872);
            boolean zH2 = c0814p2.h(lVar2) | c0814p2.f(interfaceC0773a0);
            Object objI6 = c0814p2.I();
            if (zH2 || objI6 == obj) {
                objI6 = new com.quizlet.features.questionnaire.screens.c(10, lVar2, interfaceC0773a0);
                c0814p2.i0(objI6);
            }
            Function0 function02 = (Function0) objI6;
            boolean zR = AbstractC4178x.r(c0814p2, false, -1808625286, interfaceC0773a0);
            Object objI7 = c0814p2.I();
            if (zR || objI7 == obj) {
                objI7 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 16);
                c0814p2.i0(objI7);
            }
            c0814p2.p(false);
            b(str, dVar, function0, function02, (Function1) objI7, c0814p2, (i3 << 3) & 896, 0);
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changeuseremail.a(onSuccess, function0, lVar2, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:88:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(java.lang.String r18, com.quizlet.features.settings.data.states.d r19, kotlin.jvm.functions.Function0 r20, kotlin.jvm.functions.Function0 r21, kotlin.jvm.functions.Function1 r22, androidx.compose.runtime.InterfaceC0806l r23, int r24, int r25) {
        /*
            Method dump skipped, instructions count: 324
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.T2.b(java.lang.String, com.quizlet.features.settings.data.states.d, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static com.google.android.gms.ads.h[] c(String str) {
        String[] strArrSplit = str.split("\\s*,\\s*");
        int length = strArrSplit.length;
        com.google.android.gms.ads.h[] hVarArr = new com.google.android.gms.ads.h[length];
        for (int i = 0; i < strArrSplit.length; i++) {
            String strTrim = strArrSplit[i].trim();
            if (strTrim.matches("^(\\d+|FULL_WIDTH)\\s*[xX]\\s*(\\d+|AUTO_HEIGHT)$")) {
                String[] strArrSplit2 = strTrim.split("[xX]");
                strArrSplit2[0] = strArrSplit2[0].trim();
                strArrSplit2[1] = strArrSplit2[1].trim();
                try {
                    hVarArr[i] = new com.google.android.gms.ads.h("FULL_WIDTH".equals(strArrSplit2[0]) ? -1 : Integer.parseInt(strArrSplit2[0]), "AUTO_HEIGHT".equals(strArrSplit2[1]) ? -2 : Integer.parseInt(strArrSplit2[1]));
                } catch (NumberFormatException unused) {
                    throw new IllegalArgumentException("Could not parse XML attribute \"adSize\": ".concat(strTrim));
                }
            } else if ("BANNER".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.i;
            } else if ("LARGE_BANNER".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.k;
            } else if ("FULL_BANNER".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.j;
            } else if ("LEADERBOARD".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.l;
            } else if ("MEDIUM_RECTANGLE".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.m;
            } else if ("SMART_BANNER".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.o;
            } else if ("WIDE_SKYSCRAPER".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.n;
            } else if ("FLUID".equals(strTrim)) {
                hVarArr[i] = com.google.android.gms.ads.h.p;
            } else {
                if (!"ICON".equals(strTrim)) {
                    throw new IllegalArgumentException("Could not parse XML attribute \"adSize\": ".concat(strTrim));
                }
                hVarArr[i] = com.google.android.gms.ads.h.r;
            }
        }
        if (length != 0) {
            return hVarArr;
        }
        throw new IllegalArgumentException("Could not parse XML attribute \"adSize\": ".concat(str));
    }
}
