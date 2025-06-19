package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.v5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3745v5 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:104:0x013f  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0194  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01da  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01e1  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x01fa  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x01ff  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0216  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x021b  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0246  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x024e  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0251  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x0273  */
    /* JADX WARN: Removed duplicated region for block: B:212:0x0287  */
    /* JADX WARN: Removed duplicated region for block: B:215:0x028d  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x02a1  */
    /* JADX WARN: Removed duplicated region for block: B:225:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x02b0  */
    /* JADX WARN: Removed duplicated region for block: B:236:0x02c8  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x02cb  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x02f2  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x03ae  */
    /* JADX WARN: Removed duplicated region for block: B:276:0x03b0  */
    /* JADX WARN: Removed duplicated region for block: B:278:0x03b5  */
    /* JADX WARN: Removed duplicated region for block: B:283:0x03d2  */
    /* JADX WARN: Removed duplicated region for block: B:285:0x03d5  */
    /* JADX WARN: Removed duplicated region for block: B:287:0x03d8  */
    /* JADX WARN: Removed duplicated region for block: B:289:0x03db  */
    /* JADX WARN: Removed duplicated region for block: B:290:0x03dd  */
    /* JADX WARN: Removed duplicated region for block: B:292:0x03e1  */
    /* JADX WARN: Removed duplicated region for block: B:293:0x03e3  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x03e9  */
    /* JADX WARN: Removed duplicated region for block: B:297:0x03f1  */
    /* JADX WARN: Removed duplicated region for block: B:299:0x03f5  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x03f8  */
    /* JADX WARN: Removed duplicated region for block: B:302:0x03fc  */
    /* JADX WARN: Removed duplicated region for block: B:303:0x03ff  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x0403  */
    /* JADX WARN: Removed duplicated region for block: B:306:0x0406  */
    /* JADX WARN: Removed duplicated region for block: B:308:0x040a  */
    /* JADX WARN: Removed duplicated region for block: B:309:0x040d  */
    /* JADX WARN: Removed duplicated region for block: B:311:0x0411  */
    /* JADX WARN: Removed duplicated region for block: B:312:0x0414  */
    /* JADX WARN: Removed duplicated region for block: B:314:0x0418  */
    /* JADX WARN: Removed duplicated region for block: B:315:0x041b  */
    /* JADX WARN: Removed duplicated region for block: B:317:0x041f  */
    /* JADX WARN: Removed duplicated region for block: B:318:0x0422  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x0428  */
    /* JADX WARN: Removed duplicated region for block: B:322:0x0430  */
    /* JADX WARN: Removed duplicated region for block: B:324:0x0434  */
    /* JADX WARN: Removed duplicated region for block: B:325:0x0439  */
    /* JADX WARN: Removed duplicated region for block: B:328:0x043f  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x0449  */
    /* JADX WARN: Removed duplicated region for block: B:332:0x044f  */
    /* JADX WARN: Removed duplicated region for block: B:333:0x045c  */
    /* JADX WARN: Removed duplicated region for block: B:335:0x0462  */
    /* JADX WARN: Removed duplicated region for block: B:339:0x047f  */
    /* JADX WARN: Removed duplicated region for block: B:342:0x0490  */
    /* JADX WARN: Removed duplicated region for block: B:344:0x04a8  */
    /* JADX WARN: Removed duplicated region for block: B:347:0x04bb  */
    /* JADX WARN: Removed duplicated region for block: B:348:0x04be  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:351:0x04cd  */
    /* JADX WARN: Removed duplicated region for block: B:354:0x04ea  */
    /* JADX WARN: Removed duplicated region for block: B:357:0x0501  */
    /* JADX WARN: Removed duplicated region for block: B:359:0x0512  */
    /* JADX WARN: Removed duplicated region for block: B:362:0x051c  */
    /* JADX WARN: Removed duplicated region for block: B:363:0x051e  */
    /* JADX WARN: Removed duplicated region for block: B:366:0x0556  */
    /* JADX WARN: Removed duplicated region for block: B:368:0x055b  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:371:0x0584  */
    /* JADX WARN: Removed duplicated region for block: B:373:0x0589  */
    /* JADX WARN: Removed duplicated region for block: B:376:0x05a0  */
    /* JADX WARN: Removed duplicated region for block: B:377:0x05a6  */
    /* JADX WARN: Removed duplicated region for block: B:388:0x0615  */
    /* JADX WARN: Removed duplicated region for block: B:390:0x061a  */
    /* JADX WARN: Removed duplicated region for block: B:393:0x063b  */
    /* JADX WARN: Removed duplicated region for block: B:394:0x063d  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x064a  */
    /* JADX WARN: Removed duplicated region for block: B:398:0x064c  */
    /* JADX WARN: Removed duplicated region for block: B:404:0x065f  */
    /* JADX WARN: Removed duplicated region for block: B:408:0x070b  */
    /* JADX WARN: Removed duplicated region for block: B:410:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0129  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final java.lang.String r46, androidx.compose.ui.q r47, kotlin.jvm.functions.Function1 r48, java.lang.String r49, java.lang.String r50, int r51, int r52, java.lang.Integer r53, androidx.compose.ui.focus.p r54, int r55, int r56, kotlin.jvm.functions.Function0 r57, java.lang.String r58, boolean r59, boolean r60, androidx.compose.ui.graphics.painter.b r61, int r62, com.quizlet.assembly.compose.input.r r63, float r64, androidx.compose.material3.A4 r65, androidx.compose.foundation.interaction.l r66, androidx.compose.runtime.internal.d r67, androidx.compose.runtime.InterfaceC0806l r68, final int r69, final int r70, final int r71, final int r72) {
        /*
            Method dump skipped, instructions count: 1826
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5.a(java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function1, java.lang.String, java.lang.String, int, int, java.lang.Integer, androidx.compose.ui.focus.p, int, int, kotlin.jvm.functions.Function0, java.lang.String, boolean, boolean, androidx.compose.ui.graphics.painter.b, int, com.quizlet.assembly.compose.input.r, float, androidx.compose.material3.A4, androidx.compose.foundation.interaction.l, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0186  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x018b  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x0208  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x0229  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x023f  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x025b  */
    /* JADX WARN: Removed duplicated region for block: B:199:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x02a6  */
    /* JADX WARN: Removed duplicated region for block: B:225:0x02f9  */
    /* JADX WARN: Removed duplicated region for block: B:226:0x02fb  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x0301  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0304  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x0309  */
    /* JADX WARN: Removed duplicated region for block: B:235:0x0311  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x0314  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x0316  */
    /* JADX WARN: Removed duplicated region for block: B:240:0x031a  */
    /* JADX WARN: Removed duplicated region for block: B:241:0x031d  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x0321  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0324  */
    /* JADX WARN: Removed duplicated region for block: B:246:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x032b  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x032f  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x0332  */
    /* JADX WARN: Removed duplicated region for block: B:253:0x0337  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x033b  */
    /* JADX WARN: Removed duplicated region for block: B:259:0x035b  */
    /* JADX WARN: Removed duplicated region for block: B:261:0x035f  */
    /* JADX WARN: Removed duplicated region for block: B:262:0x0361  */
    /* JADX WARN: Removed duplicated region for block: B:265:0x0367  */
    /* JADX WARN: Removed duplicated region for block: B:266:0x036c  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x0370  */
    /* JADX WARN: Removed duplicated region for block: B:271:0x0376  */
    /* JADX WARN: Removed duplicated region for block: B:272:0x0380  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x0386  */
    /* JADX WARN: Removed duplicated region for block: B:277:0x0395  */
    /* JADX WARN: Removed duplicated region for block: B:280:0x03aa  */
    /* JADX WARN: Removed duplicated region for block: B:285:0x0470  */
    /* JADX WARN: Removed duplicated region for block: B:287:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0138  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final java.lang.String r39, final kotlin.jvm.functions.Function1 r40, androidx.compose.ui.q r41, java.lang.String r42, java.lang.String r43, int r44, int r45, androidx.compose.ui.focus.p r46, int r47, int r48, kotlin.jvm.functions.Function0 r49, java.lang.String r50, boolean r51, com.quizlet.assembly.compose.input.w r52, kotlin.jvm.functions.Function0 r53, boolean r54, int r55, com.quizlet.assembly.compose.input.r r56, float r57, androidx.compose.material3.A4 r58, androidx.compose.foundation.interaction.l r59, androidx.compose.runtime.InterfaceC0806l r60, final int r61, final int r62, final int r63, final int r64) {
        /*
            Method dump skipped, instructions count: 1161
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5.b(java.lang.String, kotlin.jvm.functions.Function1, androidx.compose.ui.q, java.lang.String, java.lang.String, int, int, androidx.compose.ui.focus.p, int, int, kotlin.jvm.functions.Function0, java.lang.String, boolean, com.quizlet.assembly.compose.input.w, kotlin.jvm.functions.Function0, boolean, int, com.quizlet.assembly.compose.input.r, float, androidx.compose.material3.A4, androidx.compose.foundation.interaction.l, androidx.compose.runtime.l, int, int, int, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void c(final androidx.compose.ui.text.input.A value, final androidx.compose.ui.q qVar, final Function1 function1, int i, androidx.compose.ui.focus.p pVar, int i2, final int i3, final Function0 function0, final int i4, com.quizlet.assembly.compose.input.r rVar, InterfaceC0806l interfaceC0806l, final int i5) {
        int i6;
        androidx.compose.ui.focus.p pVar2;
        int i7;
        com.quizlet.assembly.compose.input.r rVar2;
        int i8;
        int i9;
        int i10;
        androidx.compose.runtime.internal.d dVarL;
        int i11;
        androidx.compose.ui.focus.p pVar3;
        androidx.compose.runtime.internal.d dVarE;
        C0814p c0814p;
        final int i12;
        final androidx.compose.ui.focus.p pVar4;
        final int i13;
        final com.quizlet.assembly.compose.input.r rVar3;
        Intrinsics.checkNotNullParameter(value, "value");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-187274109);
        if ((i5 & 6) == 0) {
            i6 = (c0814p2.f(value) ? 4 : 2) | i5;
        } else {
            i6 = i5;
        }
        if ((i5 & 48) == 0) {
            i6 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i5 & 384) == 0) {
            i6 |= c0814p2.h(function1) ? 256 : 128;
        }
        int i14 = 1797120 | i6;
        if ((12582912 & i5) == 0) {
            i14 = 5991424 | i6;
        }
        int i15 = 100663296 | i14;
        if ((805306368 & i5) == 0) {
            i15 |= c0814p2.d(i3) ? 536870912 : 268435456;
        }
        int i16 = (c0814p2.h(function0) ? (char) 4 : (char) 2) | 28080 | (c0814p2.d(i4) ? 131072 : 65536) | 1572864;
        if ((306783379 & i15) == 306783378 && (599187 & i16) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            i12 = i;
            i13 = i2;
            rVar3 = rVar;
            c0814p = c0814p2;
            pVar4 = pVar;
        } else {
            c0814p2.S();
            if ((i5 & 1) == 0 || c0814p2.w()) {
                pVar2 = new androidx.compose.ui.focus.p();
                i7 = i15 & (-29360129);
                rVar2 = com.quizlet.assembly.compose.input.n.a;
                i8 = 1;
                i9 = 6;
            } else {
                c0814p2.Q();
                pVar2 = pVar;
                i9 = i2;
                rVar2 = rVar;
                i7 = i15 & (-29360129);
                i8 = i;
            }
            c0814p2.q();
            boolean z = i3 == 7;
            c0814p2.X(1740325320);
            Object objI = c0814p2.I();
            androidx.compose.ui.focus.p pVar5 = pVar2;
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(Boolean.valueOf(!z));
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            int i17 = i9;
            Object objG = com.google.android.gms.measurement.internal.Z.g(1740327911, c0814p2, false);
            if (objG == v) {
                objG = new androidx.navigation.compose.z(interfaceC0773a0, 1);
                c0814p2.i0(objG);
            }
            Function0 function02 = (Function0) objG;
            c0814p2.p(false);
            if (z) {
                c0814p2.X(-1884320015);
                androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(-1015169929, new com.quizlet.assembly.compose.input.g(function02, interfaceC0773a0, 0), c0814p2);
                i11 = 0;
                c0814p2.p(false);
                dVarL = dVarE2;
                i10 = 1;
            } else {
                c0814p2.X(-1884226891);
                i10 = 1;
                dVarL = l(null, null, false, c0814p2, 1);
                i11 = 0;
                c0814p2.p(false);
            }
            int i18 = i8 == i10 ? i10 : i11;
            int i19 = i11;
            androidx.compose.runtime.internal.d dVar = dVarL;
            com.quizlet.assembly.compose.input.r rVar4 = rVar2;
            int i20 = i8;
            androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, 0L, 0L, null, null, 0L, i4, 0L, null, 16744447);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.focus.a.k(qVar, pVar5), 1.0f);
            androidx.compose.material3.A4 a4K = k(rVar4, c0814p2, 6);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            float f = com.quizlet.ui.resources.designsystem.generated.f.g;
            mVar.d();
            androidx.compose.foundation.shape.d dVarB = androidx.compose.foundation.shape.e.b(f, f, 12);
            androidx.compose.ui.text.input.K tVar = ((Boolean) interfaceC0773a0.getValue()).booleanValue() ? androidx.compose.ui.text.input.J.a : new androidx.compose.ui.text.input.t();
            C0490g0 c0490g0 = new C0490g0(i3, i17, 115);
            c0814p2.X(1740369776);
            int i21 = i16 & 14;
            int i22 = i21 == 4 ? 1 : i19;
            Object objI2 = c0814p2.I();
            if (i22 != 0 || objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.input.d(0, function0);
                c0814p2.i0(objI2);
            }
            Function1 function12 = (Function1) objI2;
            c0814p2.p(false);
            c0814p2.X(1740374000);
            boolean z2 = i21 == 4;
            Object objI3 = c0814p2.I();
            if (z2 || objI3 == v) {
                objI3 = new com.quizlet.assembly.compose.input.d(1, function0);
                c0814p2.i0(objI3);
            }
            Function1 function13 = (Function1) objI3;
            c0814p2.p(false);
            c0814p2.X(1740368368);
            boolean z3 = i21 == 4;
            Object objI4 = c0814p2.I();
            if (z3 || objI4 == v) {
                objI4 = new com.quizlet.assembly.compose.input.d(2, function0);
                c0814p2.i0(objI4);
            }
            Function1 function14 = (Function1) objI4;
            c0814p2.p(false);
            c0814p2.X(1740371248);
            boolean z4 = i21 == 4;
            Object objI5 = c0814p2.I();
            if (z4 || objI5 == v) {
                objI5 = new com.quizlet.assembly.compose.input.d(3, function0);
                c0814p2.i0(objI5);
            }
            Function1 function15 = (Function1) objI5;
            c0814p2.p(false);
            c0814p2.X(1740372656);
            boolean z5 = i21 == 4;
            Object objI6 = c0814p2.I();
            if (z5 || objI6 == v) {
                objI6 = new com.quizlet.assembly.compose.input.d(4, function0);
                c0814p2.i0(objI6);
            }
            c0814p2.p(false);
            C0488f0 c0488f0 = new C0488f0(function12, function13, function14, function15, (Function1) objI6, 8);
            androidx.compose.runtime.internal.d dVarH = h(null, c0814p2);
            androidx.compose.runtime.internal.d dVarD = d(null, c0814p2);
            androidx.compose.runtime.internal.d dVarI = i(null, c0814p2);
            androidx.compose.runtime.internal.d dVarE3 = e(null, c0814p2);
            c0814p2.X(1740384065);
            if (dVar == null) {
                pVar3 = pVar5;
                dVarE = null;
            } else {
                pVar3 = pVar5;
                dVarE = androidx.compose.runtime.internal.e.e(20500026, new com.quizlet.assembly.compose.input.f(dVar, 0), c0814p2);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            androidx.compose.material3.K4.a(value, function1, qVarC, false, lB, dVarD, dVarH, dVarE3, dVarE, dVarI, false, tVar, c0490g0, c0488f0, i18, i20, 0, dVarB, a4K, c0814p, (i7 & 14) | ((i7 >> 3) & ContentType.LONG_FORM_ON_DEMAND), (i7 << 6) & 234881024, 1575960);
            i12 = i20;
            pVar4 = pVar3;
            i13 = i17;
            rVar3 = rVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.input.e
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i5 | 1);
                    int i23 = i4;
                    r rVar5 = rVar3;
                    AbstractC3745v5.c(value, qVar, function1, i12, pVar4, i13, i3, function0, i23, rVar5, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final androidx.compose.runtime.internal.d d(String str, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1346469953);
        androidx.compose.runtime.internal.d dVarE = str == null ? null : androidx.compose.runtime.internal.e.e(658893881, new com.quizlet.assembly.compose.input.i(str, 0), c0814p);
        c0814p.p(false);
        return dVarE;
    }

    public static final androidx.compose.runtime.internal.d e(androidx.compose.ui.graphics.painter.b bVar, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1962460864);
        androidx.compose.runtime.internal.d dVarE = bVar == null ? null : androidx.compose.runtime.internal.e.e(1028106386, new com.quizlet.assembly.compose.input.j(bVar, 0), c0814p);
        c0814p.p(false);
        return dVarE;
    }

    public static final void f(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1702806478);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.h();
            AbstractC0666j3.a(androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.g), "loadingIndicator"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).k, 2, 0L, 0, c0814p, 384, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 3);
        }
    }

    public static final void g(int i, InterfaceC0806l interfaceC0806l, Function0 function0, boolean z) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1352709747);
        if ((((c0814p.g(z) ? 32 : 16) | i) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            androidx.compose.material3.Z1.h(function02, androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "passwordButton"), false, null, androidx.compose.runtime.internal.e.e(-1402847306, new com.quizlet.assembly.compose.input.k(z), c0814p), c0814p, 196662, 28);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.input.c(i, 0, function02, z);
        }
    }

    public static final androidx.compose.runtime.internal.d h(String str, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1903677184);
        androidx.compose.runtime.internal.d dVarE = str == null ? null : androidx.compose.runtime.internal.e.e(-1940274440, new com.quizlet.assembly.compose.input.i(str, 1), c0814p);
        c0814p.p(false);
        return dVarE;
    }

    public static final androidx.compose.runtime.internal.d i(String str, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-725251614);
        String str2 = str == null ? null : str;
        androidx.compose.runtime.internal.d dVarE = str2 != null ? androidx.compose.runtime.internal.e.e(1210254810, new com.quizlet.assembly.compose.input.l(0, str, str2), c0814p) : null;
        c0814p.p(false);
        return dVarE;
    }

    public static final void j(com.quizlet.assembly.compose.input.w wVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1601316414);
        int i2 = (c0814p.f(wVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else if (wVar instanceof com.quizlet.assembly.compose.input.v) {
            c0814p.X(2007112005);
            String str = ((com.quizlet.assembly.compose.input.v) wVar).a;
            c0814p.X(2007114319);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.braze.support.u(5, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3586b5.a(str, null, (Function0) objI, false, null, null, null, null, null, c0814p, 0, 1018);
            c0814p.p(false);
        } else if (wVar instanceof com.quizlet.assembly.compose.input.u) {
            c0814p.X(2091074814);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            androidx.compose.material3.D1.a(((com.quizlet.assembly.compose.input.u) wVar).a, null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.j.i), "trailingIconImage"), 0L, c0814p, 48, 8);
            c0814p.p(false);
        } else {
            c0814p.X(2091304679);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(wVar, function0, i, 3);
        }
    }

    public static final androidx.compose.material3.A4 k(com.quizlet.assembly.compose.input.r variant, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(variant, "variant");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1974567130);
        androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
        int i2 = i & 14;
        long jA = variant.a(c0814p, i2);
        long jA2 = variant.a(c0814p, i2);
        long jA3 = variant.a(c0814p, i2);
        long jA4 = variant.a(c0814p, i2);
        long jA5 = variant.a(c0814p, i2);
        long jE = AbstractC3169i5.f(c0814p).b.e();
        long jE2 = AbstractC3169i5.f(c0814p).b.e();
        long jF = AbstractC3169i5.f(c0814p).b.f();
        long jF2 = AbstractC3169i5.f(c0814p).b.f();
        long jF3 = AbstractC3169i5.f(c0814p).b.f();
        long jF4 = AbstractC3169i5.f(c0814p).b.f();
        long jE3 = AbstractC3169i5.f(c0814p).b.e();
        long jE4 = AbstractC3169i5.f(c0814p).b.e();
        long jE5 = AbstractC3169i5.f(c0814p).b.e();
        long jE6 = AbstractC3169i5.f(c0814p).b.e();
        long jA6 = AbstractC3169i5.f(c0814p).b.a();
        long jF5 = AbstractC3169i5.f(c0814p).b.f();
        long jF6 = AbstractC3169i5.f(c0814p).b.f();
        long jA7 = AbstractC3169i5.f(c0814p).b.a();
        long jA8 = AbstractC3169i5.f(c0814p).b.a();
        long jA9 = AbstractC3169i5.f(c0814p).b.a();
        long jA10 = AbstractC3169i5.f(c0814p).b.a();
        androidx.compose.material3.A4 a4C = androidx.compose.material3.D4.c(jE3, jE4, jE5, jE6, jA, jA2, jA3, jA4, jE2, jA8, new androidx.compose.foundation.text.selection.p0(AbstractC3169i5.f(c0814p).K(), AbstractC3169i5.f(c0814p).b.c()), jE, jA5, 0L, jA7, jA9, AbstractC3169i5.f(c0814p).b.f(), AbstractC3169i5.f(c0814p).b.f(), jA10, jF5, jF6, jA6, jF, jF2, jF3, jF4, c0814p, 35889152);
        c0814p.p(false);
        return a4C;
    }

    public static final androidx.compose.runtime.internal.d l(Function0 function0, com.quizlet.assembly.compose.input.w wVar, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(54508792);
        if ((i & 1) != 0) {
            c0814p.X(318242221);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new com.perimeterx.mobile_sdk.doctor_app.ui.p(15);
                c0814p.i0(objI);
            }
            function0 = (Function0) objI;
            c0814p.p(false);
        }
        androidx.compose.runtime.internal.d dVarE = z ? com.quizlet.assembly.compose.input.t.a : wVar != null ? androidx.compose.runtime.internal.e.e(1953807364, new com.quizlet.assembly.compose.input.m(0, wVar, function0), c0814p) : null;
        c0814p.p(false);
        return dVarE;
    }

    public static final androidx.compose.material3.A4 m(com.quizlet.assembly.compose.input.r variant, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(variant, "variant");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-719912720);
        androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
        long jA = variant.a(c0814p, 0);
        long jA2 = variant.a(c0814p, 0);
        long jA3 = variant.a(c0814p, 0);
        long jA4 = variant.a(c0814p, 0);
        long j = C0861v.f;
        long jE = AbstractC3169i5.f(c0814p).b.e();
        long jF = AbstractC3169i5.f(c0814p).b.f();
        long jF2 = AbstractC3169i5.f(c0814p).b.f();
        long jF3 = AbstractC3169i5.f(c0814p).b.f();
        long jF4 = AbstractC3169i5.f(c0814p).b.f();
        long jE2 = AbstractC3169i5.f(c0814p).b.e();
        long jE3 = AbstractC3169i5.f(c0814p).b.e();
        long jE4 = AbstractC3169i5.f(c0814p).b.e();
        long jE5 = AbstractC3169i5.f(c0814p).b.e();
        long jA5 = AbstractC3169i5.f(c0814p).b.a();
        long jA6 = AbstractC3169i5.f(c0814p).b.a();
        androidx.compose.material3.A4 a4C = androidx.compose.material3.D4.c(jE2, jE3, jE4, jE5, jA, jA2, jA3, jA4, jE, AbstractC3169i5.f(c0814p).b.a(), new androidx.compose.foundation.text.selection.p0(AbstractC3169i5.f(c0814p).K(), AbstractC3169i5.f(c0814p).b.c()), j, j, 0L, jA6, AbstractC3169i5.f(c0814p).b.a(), 0L, 0L, AbstractC3169i5.f(c0814p).b.a(), 0L, 0L, jA5, jF, jF2, jF3, jF4, c0814p, 62627840);
        c0814p.p(false);
        return a4C;
    }
}
