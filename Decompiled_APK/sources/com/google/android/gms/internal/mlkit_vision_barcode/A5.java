package com.google.android.gms.internal.mlkit_vision_barcode;

import android.text.Html;
import android.text.Spanned;
import android.text.style.StyleSpan;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.braze.C1483i;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A5 {
    public static final void a(boolean z, com.quizlet.assembly.compose.modals.x xVar, String str, String str2, Function1 function1, int i, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        int i4;
        Function1 function12;
        int i5;
        Function1 function13;
        int i6;
        int i7;
        int i8;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-678150594);
        if ((i2 & 6) == 0) {
            i4 = (c0814p.g(z) ? 4 : 2) | i2;
        } else {
            i4 = i2;
        }
        int i9 = i4 | (c0814p.h(xVar) ? 32 : 16);
        if ((i2 & 384) == 0) {
            i9 |= c0814p.f(str) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i9 |= c0814p.f(str2) ? 2048 : 1024;
        }
        int i10 = i3 & 16;
        if (i10 != 0) {
            i5 = i9 | 24576;
            function12 = function1;
        } else {
            function12 = function1;
            i5 = i9 | (c0814p.h(function12) ? 16384 : 8192);
        }
        int i11 = i5 | 65536;
        if ((74899 & i11) == 74898 && c0814p.x()) {
            c0814p.Q();
            i8 = i;
        } else {
            c0814p.S();
            int i12 = i2 & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i12 == 0 || c0814p.w()) {
                if (i10 != 0) {
                    c0814p.X(-1369831023);
                    Object objI = c0814p.I();
                    if (objI == v) {
                        objI = new C4237k(14);
                        c0814p.i0(objI);
                    }
                    function13 = (Function1) objI;
                    c0814p.p(false);
                } else {
                    function13 = function12;
                }
                i6 = i11 & (-458753);
                i7 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i6 = i11 & (-458753);
                function13 = function12;
                i7 = i;
            }
            c0814p.q();
            Object[] objArr = new Object[0];
            c0814p.X(-1369827209);
            boolean z2 = (i6 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new C1483i(z, 12);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI2, c0814p, 0, 6);
            AbstractC3579a6.d(null, androidx.compose.runtime.internal.e.e(-1212157956, new com.quizlet.explanations.questiondetail.ui.composables.s(i7, str, str2, interfaceC0773a0, 1), c0814p), com.quizlet.features.infra.basestudy.ui.b.a, androidx.compose.runtime.internal.e.e(25616791, new com.quizlet.features.infra.basestudy.ui.h(xVar, function13, interfaceC0773a0, 0), c0814p), null, 0, false, c0814p, 3504, ContentType.LIVE);
            c0814p = c0814p;
            i8 = i7;
            function12 = function13;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.i(z, xVar, str, str2, function12, i8, i2, i3);
        }
    }

    public static final void b(boolean z, com.quizlet.assembly.compose.modals.x modalState, String publicLabelDescriptionText, String privateLabelDescriptionText, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(publicLabelDescriptionText, "publicLabelDescriptionText");
        Intrinsics.checkNotNullParameter(privateLabelDescriptionText, "privateLabelDescriptionText");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1645376117);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(publicLabelDescriptionText) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(privateLabelDescriptionText) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function1) ? 16384 : 8192;
        }
        int i3 = i2;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(modalState, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-168922662, new com.quizlet.features.infra.basestudy.ui.i(z, modalState, publicLabelDescriptionText, privateLabelDescriptionText, function1), c0814p), c0814p, 1572872 | ((i3 >> 3) & 14), 62);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.q(z, modalState, publicLabelDescriptionText, privateLabelDescriptionText, function1, i, 1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x02d2  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x02e2  */
    /* JADX WARN: Removed duplicated region for block: B:106:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x012c  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0130  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0172  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(int r33, int r34, androidx.compose.runtime.InterfaceC0806l r35, androidx.compose.ui.q r36, java.lang.String r37, java.lang.String r38, kotlin.jvm.functions.Function0 r39, boolean r40) {
        /*
            Method dump skipped, instructions count: 758
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.A5.c(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, java.lang.String, kotlin.jvm.functions.Function0, boolean):void");
    }

    public static final void d(String str, String str2, boolean z, Function0 function0, Function0 function02, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(362140916);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.themes.m.a(c0814p));
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c(((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 896) | (i2 & 7168), 16, c0814p, null, AbstractC3106b5.d(c0814p, R.string.privacy_settings_public_label), str, function0, z);
            c((i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 3) & 7168), 16, c0814p, null, AbstractC3106b5.d(c0814p, R.string.privacy_settings_private_label), str2, function02, !z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.basestudy.ui.e(str, str2, z, function0, function02, qVar, i, 0);
        }
    }

    public static final void e(String str, String str2, boolean z, Function0 function0, Function0 function02, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-147469155);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.themes.m.a(c0814p));
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0392jG, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            String strD = AbstractC3106b5.d(c0814p, R.string.privacy_settings_public_label);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c(((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 896) | (i2 & 7168), 0, c0814p, i0.a(nVar, 1.0f, true), strD, str, function0, z);
            c((i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 3) & 7168), 0, c0814p, i0.a(nVar, 1.0f, true), AbstractC3106b5.d(c0814p, R.string.privacy_settings_private_label), str2, function02, !z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.basestudy.ui.e(str, str2, z, function0, function02, qVar, i, 1);
        }
    }

    public static final void f(String text, androidx.compose.ui.q qVar, androidx.compose.ui.text.style.i iVar, long j, androidx.compose.ui.text.L l, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.text.style.i iVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(933920496);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            iVar2 = iVar;
            i2 |= c0814p2.f(iVar2) ? 256 : 128;
        } else {
            iVar2 = iVar;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.f(l) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            Spanned spannedFromHtml = Html.fromHtml(text, 0);
            Intrinsics.checkNotNullExpressionValue(spannedFromHtml, "fromHtml(...)");
            c0814p = c0814p2;
            androidx.compose.material3.Q4.c(h(spannedFromHtml), qVar, j, 0L, null, 0L, iVar2, 0L, 0, false, 0, 0, null, null, l, c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 3) & 896) | ((i2 << 21) & 1879048192), (i2 << 9) & 29360128, 130552);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.a(text, qVar, iVar, j, l, i);
        }
    }

    public static final boolean g(androidx.compose.ui.geometry.c cVar, float f, float f2) {
        return f <= cVar.c && cVar.a <= f && f2 <= cVar.d && cVar.b <= f2;
    }

    public static final C0995g h(Spanned spanned) {
        Intrinsics.checkNotNullParameter(spanned, "<this>");
        C0984d c0984d = new C0984d();
        c0984d.f(spanned.toString());
        Object[] spans = spanned.getSpans(0, spanned.length(), Object.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            int spanStart = spanned.getSpanStart(obj);
            int spanEnd = spanned.getSpanEnd(obj);
            if (obj instanceof StyleSpan) {
                int style = ((StyleSpan) obj).getStyle();
                if (style == 1) {
                    c0984d.c(new androidx.compose.ui.text.D(0L, 0L, androidx.compose.ui.text.font.u.i, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65531), spanStart, spanEnd);
                } else if (style == 2) {
                    c0984d.c(new androidx.compose.ui.text.D(0L, 0L, (androidx.compose.ui.text.font.u) null, new androidx.compose.ui.text.font.q(1), (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65527), spanStart, spanEnd);
                }
            }
        }
        return c0984d.j();
    }
}
