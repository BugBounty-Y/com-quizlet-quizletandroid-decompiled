package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.lazy.grid.C0426a;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.C4660e;
import com.quizlet.quizletandroid.ui.library.C4661f;
import com.quizlet.quizletandroid.ui.library.data.C4650d;
import com.quizlet.quizletandroid.ui.library.data.C4651e;
import com.quizlet.quizletandroid.ui.library.data.C4652f;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y4 {
    /* JADX WARN: Removed duplicated region for block: B:104:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0176  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01d5  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01d7  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x01f9  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01fc  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01ff  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0202  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x0205  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x020d  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x021c  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x0229  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x022f  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x0250  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0263  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x030c  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x032a  */
    /* JADX WARN: Removed duplicated region for block: B:202:0x0395  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x03b7  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x0447  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x04ac  */
    /* JADX WARN: Removed duplicated region for block: B:224:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a2 A[PHI: r22
  0x00a2: PHI (r22v13 int) = (r22v0 int), (r22v6 int), (r22v7 int) binds: [B:55:0x00a0, B:65:0x00bd, B:64:0x00ba] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ca  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00ed A[PHI: r23
  0x00ed: PHI (r23v9 int) = (r23v0 int), (r23v6 int), (r23v7 int) binds: [B:80:0x00eb, B:90:0x0108, B:89:0x0105] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0114  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final java.lang.String r29, androidx.compose.ui.q r30, kotlin.jvm.functions.Function0 r31, boolean r32, boolean r33, com.quizlet.assembly.compose.buttons.InterfaceC4077b r34, com.quizlet.assembly.compose.buttons.L r35, long r36, long r38, com.quizlet.assembly.compose.buttons.InterfaceC4099y r40, androidx.compose.ui.graphics.painter.b r41, androidx.compose.ui.graphics.painter.b r42, boolean r43, androidx.compose.runtime.InterfaceC0806l r44, final int r45, final int r46, final int r47) {
        /*
            Method dump skipped, instructions count: 1217
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.a(java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function0, boolean, boolean, com.quizlet.assembly.compose.buttons.b, com.quizlet.assembly.compose.buttons.L, long, long, com.quizlet.assembly.compose.buttons.y, androidx.compose.ui.graphics.painter.b, androidx.compose.ui.graphics.painter.b, boolean, androidx.compose.runtime.l, int, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x018b  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0190  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0193  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01df  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01e6  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01eb  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01fd  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x027b  */
    /* JADX WARN: Removed duplicated region for block: B:153:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00c4 A[PHI: r20
  0x00c4: PHI (r20v14 int) = (r20v0 int), (r20v6 int), (r20v7 int) binds: [B:66:0x00c2, B:76:0x00df, B:75:0x00dc] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0114  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final java.lang.String r27, androidx.compose.ui.q r28, kotlin.jvm.functions.Function0 r29, boolean r30, com.quizlet.assembly.compose.buttons.C4076a r31, com.quizlet.assembly.compose.buttons.M r32, long r33, long r35, com.quizlet.assembly.compose.buttons.InterfaceC4099y r37, androidx.compose.runtime.internal.d r38, androidx.compose.runtime.internal.d r39, androidx.compose.runtime.InterfaceC0806l r40, final int r41, final int r42, final int r43) {
        /*
            Method dump skipped, instructions count: 655
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function0, boolean, com.quizlet.assembly.compose.buttons.a, com.quizlet.assembly.compose.buttons.M, long, long, com.quizlet.assembly.compose.buttons.y, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int, int):void");
    }

    public static final void c(kotlinx.collections.immutable.e eVar, Function1 function1, Function1 function12, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        Function1 function14;
        androidx.compose.foundation.lazy.grid.A a;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(343137760);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(eVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function13 = function1;
            i2 |= c0814p2.h(function13) ? 32 : 16;
        } else {
            function13 = function1;
        }
        if ((i & 384) == 0) {
            function14 = function12;
            i2 |= c0814p2.h(function14) ? 256 : 128;
        } else {
            function14 = function12;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.g(z) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            int iD = AbstractC3706q5.d(AbstractC3205m5.g(c0814p2).a);
            androidx.compose.foundation.lazy.grid.A a2 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            C0426a c0426a = new C0426a(iD);
            androidx.compose.foundation.layout.A0 a0C = AbstractC3706q5.c(z, c0814p2);
            InterfaceC0394k interfaceC0394kE = AbstractC3706q5.e(z);
            InterfaceC0388h interfaceC0388hB = AbstractC3706q5.b(z);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            c0814p2.X(-1670431648);
            boolean zH = ((i2 & 896) == 256) | c0814p2.h(eVar) | c0814p2.f(a2) | ((i2 & 7168) == 2048) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                C4660e c4660e = new C4660e(eVar, a2, function14, z, function13, 0);
                a = a2;
                c0814p2.i0(c4660e);
                objI = c4660e;
            } else {
                a = a2;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3155h0.b(c0426a, fillElement, a, a0C, interfaceC0394kE, interfaceC0388hB, null, false, (Function1) objI, c0814p, 48, 400);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4661f(eVar, function1, function12, z, i, 0);
        }
    }

    public static final void d(AbstractC3674m5 data, Function0 function0, Function1 function1, Function1 function12, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(740967098);
        int i2 = i | (c0814p.f(data) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.g(z) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else if (data instanceof C4650d) {
            c0814p.X(1364395047);
            c(((C4650d) data).a, function1, function12, z, c0814p, (i2 >> 3) & 8176);
            c0814p = c0814p;
            c0814p.p(false);
        } else if (Intrinsics.b(data, C4652f.a)) {
            c0814p.X(1364403002);
            AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
            c0814p.p(false);
        } else {
            if (!Intrinsics.b(data, C4651e.a)) {
                throw com.google.android.gms.measurement.internal.Z.j(1364393899, c0814p, false);
            }
            c0814p.X(-653060577);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(1614885664);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_create_class, c0814p, 0);
            c0814p.p(false);
            AbstractC3611e6.a(bVarA, AbstractC3106b5.d(c0814p, R.string.library_create_class_description), AbstractC3106b5.d(c0814p, R.string.library_create_class_button), null, AbstractC3106b5.d(c0814p, R.string.library_create_class_content_description), function0, c0814p, (i2 << 12) & 458752);
            c0814p = c0814p;
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(data, function0, function1, function12, z, i, 9);
        }
    }
}
