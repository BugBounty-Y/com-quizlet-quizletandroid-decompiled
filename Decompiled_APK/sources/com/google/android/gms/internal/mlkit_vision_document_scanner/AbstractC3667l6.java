package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.ui.text.C0995g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.l6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3667l6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(C0995g toastText, androidx.compose.ui.q qVar, String str, final Function0 function0, final Function0 function02, Function0 function03, final com.quizlet.assembly.compose.toasts.g gVar, com.quizlet.assembly.compose.toasts.f fVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        String str2;
        Intrinsics.checkNotNullParameter(toastText, "toastText");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1109163235);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(toastText) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            qVar2 = qVar;
            i2 |= c0814p.f(qVar2) ? 32 : 16;
        } else {
            qVar2 = qVar;
        }
        if ((i & 384) == 0) {
            str2 = str;
            i2 |= c0814p.f(str2) ? 256 : 128;
        } else {
            str2 = str;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(null) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function02) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.h(function03) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(gVar) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= (134217728 & i) == 0 ? c0814p.f(fVar) : c0814p.h(fVar) ? 67108864 : 33554432;
        }
        if ((38347923 & i2) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            if (((Boolean) ((androidx.compose.runtime.L0) gVar.b).getValue()).booleanValue()) {
                c0814p.X(1245533916);
                boolean zH = ((57344 & i2) == 16384) | c0814p.h(gVar);
                Object objI = c0814p.I();
                if (zH || objI == v) {
                    final int i4 = 0;
                    objI = new Function0() { // from class: com.quizlet.assembly.compose.toasts.b
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i4) {
                                case 0:
                                    function0.invoke();
                                    g gVar2 = gVar;
                                    ((L0) gVar2.b).setValue(Boolean.FALSE);
                                    break;
                                default:
                                    function0.invoke();
                                    g gVar3 = gVar;
                                    ((L0) gVar3.b).setValue(Boolean.FALSE);
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p.i0(objI);
                }
                Function0 function04 = (Function0) objI;
                c0814p.p(false);
                c0814p.X(1245537436);
                boolean zH2 = ((458752 & i2) == 131072) | c0814p.h(gVar);
                Object objI2 = c0814p.I();
                if (zH2 || objI2 == v) {
                    final int i5 = 1;
                    objI2 = new Function0() { // from class: com.quizlet.assembly.compose.toasts.b
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i5) {
                                case 0:
                                    function02.invoke();
                                    g gVar2 = gVar;
                                    ((L0) gVar2.b).setValue(Boolean.FALSE);
                                    break;
                                default:
                                    function02.invoke();
                                    g gVar3 = gVar;
                                    ((L0) gVar3.b).setValue(Boolean.FALSE);
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                int i6 = i2;
                c(toastText, qVar2, str2, function04, (Function0) objI2, fVar, c0814p, (i2 & 8190) | ((i2 >> 6) & 3670016), 0);
                c0814p.X(1245543301);
                boolean zH3 = c0814p.h(gVar) | ((i6 & 3670016) == 1048576);
                Object objI3 = c0814p.I();
                if (zH3 || objI3 == v) {
                    objI3 = new com.quizlet.assembly.compose.toasts.c(gVar, function03, null);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                C0776c.g(gVar, function03, (Function2) objI3, c0814p);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.E(toastText, qVar, str, function0, function02, function03, gVar, fVar, i, 1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0090 A[PHI: r13
  0x0090: PHI (r13v18 int) = (r13v0 int), (r13v6 int), (r13v7 int) binds: [B:48:0x008e, B:58:0x00a8, B:57:0x00a5] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(java.lang.String r21, androidx.compose.ui.q r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, kotlin.jvm.functions.Function0 r25, kotlin.jvm.functions.Function0 r26, com.quizlet.assembly.compose.toasts.g r27, com.quizlet.assembly.compose.toasts.f r28, androidx.compose.runtime.InterfaceC0806l r29, int r30, int r31) {
        /*
            Method dump skipped, instructions count: 368
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6.b(java.lang.String, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, com.quizlet.assembly.compose.toasts.g, com.quizlet.assembly.compose.toasts.f, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0240  */
    /* JADX WARN: Removed duplicated region for block: B:108:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0099 A[PHI: r11
  0x0099: PHI (r11v12 int) = (r11v0 int), (r11v6 int), (r11v7 int) binds: [B:54:0x0097, B:65:0x00b3, B:64:0x00b0] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01f4  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01f8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(androidx.compose.ui.text.C0995g r36, androidx.compose.ui.q r37, java.lang.String r38, kotlin.jvm.functions.Function0 r39, kotlin.jvm.functions.Function0 r40, com.quizlet.assembly.compose.toasts.f r41, androidx.compose.runtime.InterfaceC0806l r42, int r43, int r44) {
        /*
            Method dump skipped, instructions count: 596
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6.c(androidx.compose.ui.text.g, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, com.quizlet.assembly.compose.toasts.f, androidx.compose.runtime.l, int, int):void");
    }

    public static final com.quizlet.assembly.compose.toasts.g d(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1330400311);
        c0814p.X(-152633706);
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = new com.quizlet.assembly.compose.toasts.g(3000L);
            c0814p.i0(objI);
        }
        com.quizlet.assembly.compose.toasts.g gVar = (com.quizlet.assembly.compose.toasts.g) objI;
        c0814p.p(false);
        c0814p.p(false);
        return gVar;
    }
}
