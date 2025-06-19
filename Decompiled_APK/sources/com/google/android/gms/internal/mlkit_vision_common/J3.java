package com.google.android.gms.internal.mlkit_vision_common;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.HorizontalAlignElement;
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
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import com.google.android.gms.internal.mlkit_vision_common.J3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class J3 {
    public static final void a(final long j, final com.quizlet.features.infra.models.a aVar, final String str, final String str2, final boolean z, final androidx.compose.ui.q qVar, final kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, final int i) {
        String str3;
        kotlin.jvm.functions.c cVar2;
        int i2;
        androidx.compose.runtime.V v;
        boolean z2;
        Object aVar2;
        androidx.compose.ui.q qVar2;
        char c;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1025610576);
        int i3 = (c0814p.e(j) ? 4 : 2) | i;
        if ((i & 48) == 0) {
            i3 |= c0814p.f(aVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            str3 = str2;
            i3 |= c0814p.f(str3) ? 2048 : 1024;
        } else {
            str3 = str2;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.g(z) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.f(qVar) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            cVar2 = cVar;
            i3 |= c0814p.h(cVar2) ? 1048576 : 524288;
        } else {
            cVar2 = cVar;
        }
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v2 = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.m, c0814p, 6);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(-1657636074);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (aVar != null) {
                androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.platform.N.G(nVar, "term_definition_rich_text"), 1.0f);
                c0814p.X(1769354087);
                boolean z3 = ((3670016 & i3) == 1048576) | ((i3 & 14) == 4) | ((57344 & i3) == 16384) | ((i3 & 7168) == 2048);
                Object objI = c0814p.I();
                if (z3 || objI == v2) {
                    qVar2 = qVarC3;
                    c = 6;
                    aVar2 = new com.quizlet.features.termlist.ui.composables.a(cVar2, j, z, str3, 0);
                    c0814p.i0(aVar2);
                } else {
                    aVar2 = objI;
                    qVar2 = qVarC3;
                    c = 6;
                }
                c0814p.p(false);
                i2 = i3;
                z2 = false;
                v = v2;
                AbstractC3164i0.c(aVar.c, aVar.a, aVar.d, aVar.b, AbstractC0460p.l(qVar2, false, null, (Function0) aVar2, 7), ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0, 0, null, null, c0814p, 0, 0, 1920);
                c0814p = c0814p;
            } else {
                i2 = i3;
                v = v2;
                z2 = false;
            }
            c0814p.p(z2);
            c0814p.X(-1657615208);
            if (str != null && !StringsKt.O(str)) {
                com.quizlet.assembly.compose.modals.x xVarH = Y5.h(z2, z2, c0814p, 48, 5);
                androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.e(androidx.compose.ui.platform.N.G(nVar, "term_definition_image"), com.quizlet.themes.m.q, com.quizlet.themes.m.q0).g(new HorizontalAlignElement(androidx.compose.ui.b.n));
                c0814p.X(-1657596622);
                boolean zH = c0814p.h(xVarH);
                Object objI2 = c0814p.I();
                if (zH || objI2 == v) {
                    objI2 = new com.quizlet.features.folders.changetags.composables.f(xVarH, 13);
                    c0814p.i0(objI2);
                }
                c0814p.p(z2);
                int i5 = (i2 >> 6) & 14;
                com.google.android.gms.internal.mlkit_vision_camera.r3.a(str, null, AbstractC0460p.l(qVarG, z2, null, (Function0) objI2, 7), null, null, null, c0814p, i5 | 48, 2040);
                Z5.c(str, null, xVarH, c0814p, i5 | com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
            }
            c0814p.p(z2);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.termlist.ui.composables.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    q qVar3 = qVar;
                    kotlin.jvm.functions.c cVar3 = cVar;
                    J3.a(j, aVar, str, str2, z, qVar3, cVar3, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static String b(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = android.support.v4.media.session.a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }
}
