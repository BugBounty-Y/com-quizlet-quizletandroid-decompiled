package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0982b;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.j5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3178j5 {
    public static C0982b a(String str, androidx.compose.ui.text.L l, long j, androidx.compose.ui.unit.b bVar, androidx.compose.ui.text.font.i iVar, kotlin.collections.K k, int i, int i2) {
        if ((i2 & 32) != 0) {
            k = kotlin.collections.K.a;
        }
        kotlin.collections.K k2 = k;
        kotlin.collections.K k3 = kotlin.collections.K.a;
        if ((i2 & 128) != 0) {
            i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        return new C0982b(new androidx.compose.ui.text.platform.c(str, l, k2, k3, iVar, bVar), i, false, j);
    }

    public static final void b(androidx.compose.material3.windowsizeclass.b bVar, boolean z, com.quizlet.themes.h hVar, androidx.compose.runtime.internal.d content, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.material3.windowsizeclass.b bVarG;
        boolean zQ;
        int i4;
        boolean z2;
        com.quizlet.themes.h hVar2;
        com.quizlet.themes.h hVar3;
        boolean z3;
        androidx.compose.material3.windowsizeclass.b bVar2;
        Intrinsics.checkNotNullParameter(content, "content");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1664111736);
        if ((i & 6) == 0) {
            i3 = (((i2 & 1) == 0 && c0814p.f(bVar)) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= ((i2 & 2) == 0 && c0814p.g(z)) ? 32 : 16;
        }
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.f(hVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(content) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            bVar2 = bVar;
            z3 = z;
            hVar3 = hVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if ((i2 & 1) != 0) {
                    bVarG = AbstractC3205m5.g(c0814p);
                    i3 &= -15;
                } else {
                    bVarG = bVar;
                }
                if ((i2 & 2) != 0) {
                    zQ = AbstractC0460p.q(c0814p);
                    i3 &= -113;
                } else {
                    zQ = z;
                }
                if (i5 != 0) {
                    i4 = i3;
                    z2 = zQ;
                    hVar2 = com.quizlet.themes.i.b;
                } else {
                    i4 = i3;
                    z2 = zQ;
                    hVar2 = hVar;
                }
            } else {
                c0814p.Q();
                if ((i2 & 1) != 0) {
                    i3 &= -15;
                }
                if ((i2 & 2) != 0) {
                    i3 &= -113;
                }
                bVarG = bVar;
                hVar2 = hVar;
                i4 = i3;
                z2 = z;
            }
            c0814p.q();
            c(bVarG, z2, hVar2, content, c0814p, i4 & 8190, 0);
            hVar3 = hVar2;
            z3 = z2;
            bVar2 = bVarG;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.themes.v(bVar2, z3, hVar3, content, i, i2, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00df  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x010c  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0134  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0151  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0158  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x015c  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01a7  */
    /* JADX WARN: Removed duplicated region for block: B:99:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(androidx.compose.material3.windowsizeclass.b r16, boolean r17, com.quizlet.themes.h r18, androidx.compose.runtime.internal.d r19, androidx.compose.runtime.InterfaceC0806l r20, int r21, int r22) {
        /*
            Method dump skipped, instructions count: 437
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5.c(androidx.compose.material3.windowsizeclass.b, boolean, com.quizlet.themes.h, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void d(com.quizlet.ui.models.content.listitem.o oVar, Function0 onClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(oVar, "<this>");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(214165342);
        int i2 = i | (c0814p.h(oVar) ? 4 : 2) | (c0814p.h(onClick) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).j;
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).l;
            com.quizlet.themes.m.g.w();
            float f = com.quizlet.ui.resources.designsystem.generated.j.f;
            float f2 = com.quizlet.themes.m.Z0;
            float f3 = com.quizlet.themes.m.a1;
            if (oVar instanceof com.quizlet.ui.models.content.listitem.l) {
                c0814p.X(-1050548558);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.g(((com.quizlet.ui.models.content.listitem.l) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f, f2, f3, c0814p, 12582912 | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 12) & 458752), 28);
                c0814p = c0814p;
                c0814p.p(false);
            } else if (oVar instanceof com.quizlet.ui.models.content.listitem.i) {
                c0814p.X(-1050086503);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.l(((com.quizlet.ui.models.content.listitem.i) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f, f2, f3, c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912 | ((i2 << 12) & 458752), 28);
                c0814p = c0814p;
                c0814p.p(false);
            } else if (oVar instanceof com.quizlet.ui.models.content.listitem.j) {
                c0814p.X(-1049623797);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.n(((com.quizlet.ui.models.content.listitem.j) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f2, f3, c0814p, ((i2 << 12) & 458752) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 28);
                c0814p.p(false);
            } else if (oVar instanceof com.quizlet.ui.models.content.listitem.k) {
                c0814p.X(-1049214039);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.e(((com.quizlet.ui.models.content.listitem.k) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f2, f3, c0814p, ((i2 << 12) & 458752) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 28);
                c0814p.p(false);
            } else if (oVar instanceof com.quizlet.ui.models.content.listitem.h) {
                c0814p.X(-1048804591);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.i(((com.quizlet.ui.models.content.listitem.h) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f2, f3, c0814p, ((i2 << 12) & 458752) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 28);
                c0814p.p(false);
            } else if (oVar instanceof com.quizlet.ui.models.content.listitem.n) {
                c0814p.X(-1048400785);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.p(((com.quizlet.ui.models.content.listitem.n) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f2, f3, c0814p, ((i2 << 12) & 458752) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 28);
                c0814p.p(false);
            } else {
                if (!(oVar instanceof com.quizlet.ui.models.content.listitem.m)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-865171948, c0814p, false);
                }
                c0814p.X(-1047986873);
                com.google.android.gms.internal.mlkit_vision_document_scanner.C5.r(((com.quizlet.ui.models.content.listitem.m) oVar).a, qVar, false, null, false, onClick, l, 2, l2, f2, f3, c0814p, ((i2 << 12) & 458752) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 28);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(oVar, onClick, qVar, i, 24);
        }
    }
}
