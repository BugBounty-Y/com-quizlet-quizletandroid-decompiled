package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.z5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3777z5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String text, androidx.compose.ui.q qVar, com.quizlet.assembly.compose.links.i iVar, androidx.compose.foundation.layout.A0 a0, com.quizlet.assembly.compose.links.b bVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.foundation.layout.A0 a02;
        com.quizlet.assembly.compose.links.i iVar2;
        int i4;
        androidx.compose.ui.q qVar2;
        com.quizlet.assembly.compose.links.b bVar2;
        androidx.compose.foundation.layout.A0 a03;
        androidx.compose.ui.q qVar3;
        com.quizlet.assembly.compose.links.i iVar3;
        androidx.compose.foundation.layout.A0 a04;
        com.quizlet.assembly.compose.links.b bVar3;
        com.quizlet.assembly.compose.links.i iVar4 = iVar;
        com.quizlet.assembly.compose.links.b bVar4 = bVar;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-564816353);
        if ((i & 6) == 0) {
            i3 = (c0814p.f(text) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 |= 48;
        } else if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i6 = i2 & 4;
        if (i6 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(iVar4) : c0814p.h(iVar4) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            if ((i2 & 8) == 0) {
                a02 = a0;
                int i7 = c0814p.f(a02) ? 2048 : 1024;
                i3 |= i7;
            } else {
                a02 = a0;
            }
            i3 |= i7;
        } else {
            a02 = a0;
        }
        int i8 = i2 & 16;
        if (i8 != 0) {
            i3 |= 24576;
        } else if ((i & 24576) == 0) {
            i3 |= (32768 & i) == 0 ? c0814p.f(bVar4) : c0814p.h(bVar4) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            iVar3 = iVar4;
            bVar3 = bVar4;
            a04 = a02;
            qVar3 = qVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.q qVar4 = i5 != 0 ? androidx.compose.ui.n.b : qVar;
                if (i6 != 0) {
                    iVar4 = com.quizlet.assembly.compose.links.f.a;
                }
                if ((i2 & 8) != 0) {
                    com.quizlet.themes.m.g.r();
                    float f = com.quizlet.ui.resources.designsystem.generated.j.e;
                    i3 &= -7169;
                    a02 = new androidx.compose.foundation.layout.A0(f, f, f, f);
                }
                if (i8 != 0) {
                    bVar4 = null;
                }
                androidx.compose.ui.q qVar5 = qVar4;
                iVar2 = iVar4;
                i4 = i3;
                qVar2 = qVar5;
                bVar2 = bVar4;
                a03 = a02;
            } else {
                c0814p.Q();
                if ((i2 & 8) != 0) {
                    i3 &= -7169;
                }
                iVar2 = iVar4;
                bVar2 = bVar4;
                i4 = i3;
                a03 = a02;
                qVar2 = qVar;
            }
            c0814p.q();
            int i9 = i4 & 14;
            int i10 = i4 << 3;
            AbstractC3761x5.a(text, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).k, qVar2, iVar2, a03, bVar2, function0, c0814p, i9 | (i10 & 896) | (i10 & 7168) | (57344 & i10) | (458752 & i10) | (i10 & 3670016), 0);
            qVar3 = qVar2;
            iVar3 = iVar2;
            a04 = a03;
            bVar3 = bVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.links.j(text, qVar3, iVar3, a04, bVar3, function0, i, i2, 1);
        }
    }
}
