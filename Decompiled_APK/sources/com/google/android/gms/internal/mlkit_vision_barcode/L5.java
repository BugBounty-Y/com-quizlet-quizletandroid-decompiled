package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.quizlet.features.flashcards.C4242p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public abstract class L5 {
    public static final long a(int i, int i2, int i3, int i4) {
        boolean z = false;
        if (!(i2 >= i)) {
            O5.e("maxWidth(" + i2 + ") must be >= than minWidth(" + i + ')');
            throw null;
        }
        if (!(i4 >= i3)) {
            O5.e("maxHeight(" + i4 + ") must be >= than minHeight(" + i3 + ')');
            throw null;
        }
        if (i >= 0 && i3 >= 0) {
            z = true;
        }
        if (z) {
            return m(i, i2, i3, i4);
        }
        O5.e("minWidth(" + i + ") and minHeight(" + i3 + ") must be >= 0");
        throw null;
    }

    public static /* synthetic */ long b(int i, int i2, int i3) {
        if ((i3 & 2) != 0) {
            i = Integer.MAX_VALUE;
        }
        if ((i3 & 8) != 0) {
            i2 = Integer.MAX_VALUE;
        }
        return a(0, i, 0, i2);
    }

    public static final void c(com.quizlet.assembly.compose.modals.x xVar, com.quizlet.assembly.compose.modals.x xVar2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-474419577);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(xVar) : c0814p.h(xVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(xVar2) : c0814p.h(xVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        int i3 = i2;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i4 = (i3 << 18) & 234881024;
            com.google.android.gms.internal.mlkit_vision_document_scanner.P5.a(AbstractC3106b5.d(c0814p, R.string.client_error_net_exception), null, null, xVar, null, null, null, null, function0, null, c0814p, 4096 | ((i3 << 9) & 7168) | i4, 758);
            com.google.android.gms.internal.mlkit_vision_document_scanner.P5.a(AbstractC3106b5.d(c0814p, R.string.create_folder_offline_info_dialog_description), null, AbstractC3106b5.d(c0814p, R.string.create_folder_offline_info_dialog_title), xVar2, AbstractC3106b5.d(c0814p, R.string.got_it), null, null, null, function0, null, c0814p, 4096 | ((i3 << 6) & 7168) | i4, 738);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 13, xVar, xVar2, function0);
        }
    }

    public static final void d(final com.quizlet.assembly.compose.modals.x xVar, final com.quizlet.features.infra.folder.create.coursefolder.data.m mVar, final String str, final com.quizlet.features.infra.folder.create.data.b bVar, Function1 function1, final Function0 function0, final kotlinx.collections.immutable.b bVar2, final boolean z, final boolean z2, final Function1 function12, final Function0 function02, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        String str2;
        com.quizlet.features.infra.folder.create.data.b bVar3;
        kotlinx.collections.immutable.b bVar4;
        boolean z3;
        boolean z4;
        Function1 function13;
        Function0 function03;
        int i4;
        Function1 function14;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(267980902);
        if ((i & 6) == 0) {
            i3 = ((i & 8) == 0 ? c0814p2.f(xVar) : c0814p2.h(xVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= (i & 64) == 0 ? c0814p2.f(mVar) : c0814p2.h(mVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            str2 = str;
            i3 |= c0814p2.f(str2) ? 256 : 128;
        } else {
            str2 = str;
        }
        if ((i & 3072) == 0) {
            bVar3 = bVar;
            i3 |= c0814p2.f(bVar3) ? 2048 : 1024;
        } else {
            bVar3 = bVar;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(function1) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(function0) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            bVar4 = bVar2;
            i3 |= c0814p2.h(bVar4) ? 1048576 : 524288;
        } else {
            bVar4 = bVar2;
        }
        if ((12582912 & i) == 0) {
            z3 = z;
            i3 |= c0814p2.g(z3) ? 8388608 : 4194304;
        } else {
            z3 = z;
        }
        if ((100663296 & i) == 0) {
            z4 = z2;
            i3 |= c0814p2.g(z4) ? 67108864 : 33554432;
        } else {
            z4 = z2;
        }
        if ((805306368 & i) == 0) {
            function13 = function12;
            i3 |= c0814p2.h(function13) ? 536870912 : 268435456;
        } else {
            function13 = function12;
        }
        int i5 = i3;
        if ((i2 & 6) == 0) {
            function03 = function02;
            i4 = i2 | (c0814p2.h(function03) ? 4 : 2);
        } else {
            function03 = function02;
            i4 = i2;
        }
        if ((i5 & 306783379) == 306783378 && (i4 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            function14 = function1;
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.modals.x xVarH = com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(true, false, c0814p2, 6, 6);
            int i6 = i5 << 3;
            K5.a(mVar, str2, xVar, xVarH, bVar3, function1, bVar4, z3, z4, function13, function03, function0, c0814p2, ((i5 >> 3) & 126) | com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH | ((i5 << 6) & 896) | 4096 | (i6 & 57344) | (i6 & 458752) | (i5 & 3670016) | (i5 & 29360128) | (i5 & 234881024) | (i5 & 1879048192), (i4 & 14) | ((i5 >> 12) & ContentType.LONG_FORM_ON_DEMAND));
            function14 = function1;
            c0814p = c0814p2;
            c0814p.X(1112459266);
            int i7 = i5 & 57344;
            boolean z5 = i7 == 16384;
            Object objI = c0814p.I();
            if (z5 || objI == v) {
                objI = new androidx.navigation.compose.B(26, function14);
                c0814p.i0(objI);
            }
            Function1 function15 = (Function1) objI;
            c0814p.p(false);
            c0814p.X(1112464386);
            boolean z6 = i7 == 16384;
            Object objI2 = c0814p.I();
            if (z6 || objI2 == v) {
                objI2 = new androidx.navigation.compose.B(27, function14);
                c0814p.i0(objI2);
            }
            Function1 function16 = (Function1) objI2;
            c0814p.p(false);
            c0814p.X(1112469396);
            boolean zH = c0814p.h(xVarH);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                objI3 = new C4242p(0, xVarH, com.quizlet.assembly.compose.modals.x.class, "hide", "hide()V", 0, 25);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            U5.a(xVarH, null, function15, function16, (Function0) ((kotlin.reflect.f) objI3), c0814p, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final Function1 function17 = function14;
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.infra.folder.create.composables.h
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    int iH2 = C0776c.H(i2);
                    com.quizlet.features.infra.folder.create.data.b bVar5 = bVar;
                    Function1 function18 = function12;
                    Function0 function04 = function02;
                    L5.d(xVar, mVar, str, bVar5, function17, function0, bVar2, z, z2, function18, function04, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0137  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0149  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0167  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0183  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01c1  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01c5  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x01e8  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01ec  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x020e  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x022c  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x023a  */
    /* JADX WARN: Removed duplicated region for block: B:226:0x0496  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x0499  */
    /* JADX WARN: Removed duplicated region for block: B:230:0x04a1  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x04a4  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x04ac  */
    /* JADX WARN: Removed duplicated region for block: B:235:0x04af  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x04c3  */
    /* JADX WARN: Removed duplicated region for block: B:246:0x04ef  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x0508  */
    /* JADX WARN: Removed duplicated region for block: B:250:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0115  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x011c  */
    /* JADX WARN: Type inference failed for: r14v1 */
    /* JADX WARN: Type inference failed for: r14v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r14v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(final com.quizlet.assembly.compose.modals.x r41, final java.lang.String r42, java.lang.Long r43, com.quizlet.features.infra.folder.create.data.i r44, final com.quizlet.features.infra.folder.create.data.b r45, kotlinx.collections.immutable.b r46, boolean r47, boolean r48, kotlin.jvm.functions.Function1 r49, kotlin.jvm.functions.Function0 r50, final kotlin.jvm.functions.d r51, kotlin.jvm.functions.Function0 r52, com.quizlet.features.infra.folder.create.coursefolder.viewmodel.f r53, androidx.compose.runtime.InterfaceC0806l r54, final int r55, final int r56) {
        /*
            Method dump skipped, instructions count: 1296
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.L5.e(com.quizlet.assembly.compose.modals.x, java.lang.String, java.lang.Long, com.quizlet.features.infra.folder.create.data.i, com.quizlet.features.infra.folder.create.data.b, kotlinx.collections.immutable.b, boolean, boolean, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.d, kotlin.jvm.functions.Function0, com.quizlet.features.infra.folder.create.coursefolder.viewmodel.f, androidx.compose.runtime.l, int, int):void");
    }

    public static final void f(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-102909328);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        }
        if ((i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                qVar = androidx.compose.ui.n.b;
            }
            androidx.compose.ui.q qVar2 = qVar;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.c();
            float f = com.quizlet.ui.resources.designsystem.generated.f.h;
            androidx.compose.ui.q qVarL = androidx.compose.foundation.layout.K0.l(AbstractC0382e.y(qVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.p, com.quizlet.themes.m.o);
            long jS = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).s();
            mVar.c();
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarL, jS, androidx.compose.foundation.shape.e.a(f));
            mVar.c();
            AbstractC0409s.a(androidx.compose.ui.platform.N.G(androidx.compose.ui.draw.g.c(qVarF, androidx.compose.foundation.shape.e.a(f)), "drag_handle"), c0814p, 0);
            qVar = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.r(qVar, i, i2, 3);
        }
    }

    public static final int g(int i) {
        if (i < 8191) {
            return 262142;
        }
        if (i < 32767) {
            return 65534;
        }
        if (i < 65535) {
            return 32766;
        }
        if (i < 262143) {
            return 8190;
        }
        throw new IllegalArgumentException(AbstractC0147y.c(i, "Can't represent a size of ", " in Constraints"));
    }

    public static final int h(int i) {
        if (i < 8191) {
            return 13;
        }
        if (i < 32767) {
            return 15;
        }
        if (i < 65535) {
            return 16;
        }
        return i < 262143 ? 18 : 255;
    }

    public static final long i(long j, long j2) {
        return R5.a(kotlin.ranges.l.c((int) (j2 >> 32), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j)), kotlin.ranges.l.c((int) (j2 & 4294967295L), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j)));
    }

    public static final long j(long j, long j2) {
        return a(kotlin.ranges.l.c(androidx.compose.ui.unit.a.j(j2), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j)), kotlin.ranges.l.c(androidx.compose.ui.unit.a.h(j2), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j)), kotlin.ranges.l.c(androidx.compose.ui.unit.a.i(j2), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j)), kotlin.ranges.l.c(androidx.compose.ui.unit.a.g(j2), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j)));
    }

    public static final int k(int i, long j) {
        return kotlin.ranges.l.c(i, androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j));
    }

    public static final int l(int i, long j) {
        return kotlin.ranges.l.c(i, androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j));
    }

    public static final long m(int i, int i2, int i3, int i4) {
        int i5 = i4 == Integer.MAX_VALUE ? i3 : i4;
        int iH = h(i5);
        int i6 = i2 == Integer.MAX_VALUE ? i : i2;
        int iH2 = h(i6);
        if (iH + iH2 > 31) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.j("Can't represent a width of ", i6, " and height of ", " in Constraints", i5));
        }
        int i7 = i2 + 1;
        int i8 = i7 & (~(i7 >> 31));
        int i9 = i4 + 1;
        int i10 = i9 & (~(i9 >> 31));
        int i11 = 0;
        if (iH2 != 13) {
            if (iH2 == 18) {
                i11 = 3;
            } else if (iH2 == 15) {
                i11 = 1;
            } else if (iH2 == 16) {
                i11 = 2;
            }
        }
        int i12 = (((i11 & 2) >> 1) * 3) + ((i11 & 1) << 1);
        return (i8 << 33) | i11 | (i << 2) | (i3 << (i12 + 15)) | (i10 << (i12 + 46));
    }

    public static final boolean n(long j, long j2) {
        int iJ = androidx.compose.ui.unit.a.j(j);
        int iH = androidx.compose.ui.unit.a.h(j);
        int i = (int) (j2 >> 32);
        if (iJ > i || i > iH) {
            return false;
        }
        int i2 = (int) (j2 & 4294967295L);
        return androidx.compose.ui.unit.a.i(j) <= i2 && i2 <= androidx.compose.ui.unit.a.g(j);
    }

    public static final long o(int i, int i2, long j) {
        int iJ = androidx.compose.ui.unit.a.j(j) + i;
        if (iJ < 0) {
            iJ = 0;
        }
        int iH = androidx.compose.ui.unit.a.h(j);
        if (iH != Integer.MAX_VALUE && (iH = iH + i) < 0) {
            iH = 0;
        }
        int i3 = androidx.compose.ui.unit.a.i(j) + i2;
        if (i3 < 0) {
            i3 = 0;
        }
        int iG = androidx.compose.ui.unit.a.g(j);
        return a(iJ, iH, i3, (iG == Integer.MAX_VALUE || (iG = iG + i2) >= 0) ? iG : 0);
    }

    public static /* synthetic */ long p(long j, int i, int i2, int i3) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = 0;
        }
        return o(i, i2, j);
    }
}
