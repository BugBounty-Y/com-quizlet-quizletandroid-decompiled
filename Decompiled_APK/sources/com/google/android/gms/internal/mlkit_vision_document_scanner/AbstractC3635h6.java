package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.interaction.l;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3635h6;
import com.quizlet.ui.compose.C4832z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.h6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3635h6 {
    public static final void a(final androidx.compose.ui.graphics.painter.b icon, final String contentDescription, final Function0 onClick, final androidx.compose.ui.q qVar, final boolean z, final C4832z c4832z, final com.quizlet.assembly.compose.tags.j jVar, final float f, final C0555x c0555x, androidx.compose.foundation.interaction.l lVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        boolean z2;
        C4832z c4832z2;
        C0555x c0555x2;
        androidx.compose.foundation.interaction.l lVar2;
        final androidx.compose.foundation.interaction.l lVar3;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(contentDescription, "contentDescription");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-531139358);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(false) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(icon) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(contentDescription) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(onClick) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            z2 = z;
            i2 |= c0814p.g(z2) ? 131072 : 65536;
        } else {
            z2 = z;
        }
        if ((1572864 & i) == 0) {
            c4832z2 = c4832z;
            i2 |= c0814p.f(c4832z2) ? 1048576 : 524288;
        } else {
            c4832z2 = c4832z;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(jVar) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.c(f) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            c0555x2 = c0555x;
            i2 |= c0814p.f(c0555x2) ? 536870912 : 268435456;
        } else {
            c0555x2 = c0555x;
        }
        if ((306783379 & i2) == 306783378 && c0814p.x()) {
            c0814p.Q();
            lVar3 = lVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.X(352971686);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = androidx.compose.animation.d0.i(c0814p);
                }
                lVar2 = (androidx.compose.foundation.interaction.l) objI;
                c0814p.p(false);
            } else {
                c0814p.Q();
                lVar2 = lVar;
            }
            c0814p.q();
            float f2 = com.quizlet.assembly.compose.tags.g.a;
            com.quizlet.themes.m.g.b();
            int i3 = i2 >> 6;
            int i4 = i2 >> 9;
            boolean z3 = z2;
            C4832z c4832z3 = c4832z2;
            C0555x c0555x3 = c0555x2;
            androidx.compose.foundation.interaction.l lVar4 = lVar2;
            com.quizlet.ui.compose.c0.a(onClick, z3, androidx.compose.runtime.internal.e.e(-8837441, new com.quizlet.assembly.compose.tags.c(icon, contentDescription, f), c0814p), c4832z3, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j), c0555x3, com.quizlet.assembly.compose.tags.g.b(jVar), com.quizlet.assembly.compose.tags.g.c(jVar), lVar4, qVar, c0814p, (i4 & 3670016) | (i4 & 896) | (i2 & 14) | 3072 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 57344) | 805306368, (i2 >> 12) & 14);
            lVar3 = lVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.tags.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    C4832z c4832z4 = c4832z;
                    C0555x c0555x4 = c0555x;
                    l lVar5 = lVar3;
                    AbstractC3635h6.a(icon, contentDescription, onClick, qVar, z, c4832z4, jVar, f, c0555x4, lVar5, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01c2  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01c9  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01eb  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01f2  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0205  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x02b8  */
    /* JADX WARN: Removed duplicated region for block: B:146:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x013d  */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5, types: [int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final boolean r28, final java.lang.String r29, final kotlin.jvm.functions.Function0 r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.ui.text.L r33, int r34, int r35, androidx.compose.ui.graphics.painter.b r36, java.lang.String r37, com.quizlet.ui.compose.C4832z r38, com.quizlet.assembly.compose.tags.j r39, androidx.compose.foundation.C0555x r40, androidx.compose.foundation.interaction.l r41, androidx.compose.runtime.InterfaceC0806l r42, final int r43, final int r44, final int r45) {
        /*
            Method dump skipped, instructions count: 719
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3635h6.b(boolean, java.lang.String, kotlin.jvm.functions.Function0, androidx.compose.ui.q, boolean, androidx.compose.ui.text.L, int, int, androidx.compose.ui.graphics.painter.b, java.lang.String, com.quizlet.ui.compose.z, com.quizlet.assembly.compose.tags.j, androidx.compose.foundation.x, androidx.compose.foundation.interaction.l, androidx.compose.runtime.l, int, int, int):void");
    }

    public static final void c(com.quizlet.quizletandroid.ui.startpage.nav2.model.M m, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l, InterfaceC0806l interfaceC0806l, int i) {
        float f;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(974023198);
        int i2 = (c0814p2.f(m) ? 4 : 2) | i | (c0814p2.f(l) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-1019334757);
            boolean z = m.f;
            com.quizlet.generated.enums.S0 s0 = m.d;
            String strE = z ? com.google.android.gms.internal.mlkit_vision_barcode.Y5.e(s0) : com.google.android.gms.internal.mlkit_vision_barcode.Y5.a(s0, m.e).a((Context) c0814p2.j(AndroidCompositionLocals_androidKt.b));
            c0814p2.p(false);
            String strE2 = AbstractC3053s1.e(com.google.android.gms.internal.mlkit_vision_barcode.Y5.d(s0), (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b));
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (m.a) {
                com.quizlet.themes.m.g.s();
                f = com.quizlet.ui.resources.designsystem.generated.j.h;
            } else {
                com.quizlet.themes.m.g.r();
                f = com.quizlet.ui.resources.designsystem.generated.j.e;
            }
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7);
            com.quizlet.themes.m.g.q();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarY, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2);
            c0814p2.X(-1019326024);
            boolean z2 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 14) == 4);
            Object objI = c0814p2.I();
            if (z2 || objI == C0804k.a) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(0, l, m);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            R4.a(qVarW, null, 0L, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-803926952, new com.quizlet.assembly.compose.menu.l(m, strE2, strE, 29), c0814p2), c0814p, 0, 990);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(m, l, i, 24);
        }
    }
}
