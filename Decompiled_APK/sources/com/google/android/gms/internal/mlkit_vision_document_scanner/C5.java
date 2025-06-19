package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final String str, final com.quizlet.assembly.compose.listitems.k kVar, final androidx.compose.ui.q qVar, final boolean z, final androidx.compose.runtime.internal.d dVar, final boolean z2, final Function0 function0, androidx.compose.ui.text.L l, int i, androidx.compose.ui.text.L l2, float f, float f2, InterfaceC0806l interfaceC0806l, final int i2, final int i3, final int i4) {
        int i5;
        androidx.compose.ui.q qVar2;
        boolean z3;
        androidx.compose.runtime.internal.d dVar2;
        androidx.compose.ui.text.L l3;
        final int i6;
        final androidx.compose.ui.text.L l4;
        int i7;
        androidx.compose.ui.text.L l5;
        androidx.compose.ui.text.L l6;
        float f3;
        float f4;
        androidx.compose.ui.text.L l7;
        int i8;
        androidx.compose.ui.text.L l8;
        float f5;
        C0814p c0814p;
        final androidx.compose.ui.text.L l9;
        final float f6;
        final float f7;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1739765338);
        if ((i2 & 6) == 0) {
            i5 = (c0814p2.f(str) ? 4 : 2) | i2;
        } else {
            i5 = i2;
        }
        if ((i2 & 48) == 0) {
            i5 |= c0814p2.f(kVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            qVar2 = qVar;
            i5 |= c0814p2.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        int i9 = i5 | 3072;
        if ((i2 & 24576) == 0) {
            z3 = z;
            i9 |= c0814p2.g(z3) ? 16384 : 8192;
        } else {
            z3 = z;
        }
        if ((196608 & i2) == 0) {
            dVar2 = dVar;
            i9 |= c0814p2.h(dVar2) ? 131072 : 65536;
        } else {
            dVar2 = dVar;
        }
        if ((i2 & 1572864) == 0) {
            i9 |= c0814p2.g(z2) ? 1048576 : 524288;
        }
        if ((i2 & 12582912) == 0) {
            i9 |= c0814p2.h(function0) ? 8388608 : 4194304;
        }
        if ((i2 & 100663296) == 0) {
            if ((i4 & 256) == 0) {
                l3 = l;
                int i10 = c0814p2.f(l3) ? 67108864 : 33554432;
                i9 |= i10;
            } else {
                l3 = l;
            }
            i9 |= i10;
        } else {
            l3 = l;
        }
        int i11 = i4 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        if (i11 != 0) {
            i9 |= 805306368;
            i6 = i;
        } else {
            i6 = i;
            if ((i2 & 805306368) == 0) {
                i9 |= c0814p2.d(i6) ? 536870912 : 268435456;
            }
        }
        if ((i3 & 6) == 0) {
            if ((i4 & 1024) == 0) {
                l4 = l2;
                int i12 = c0814p2.f(l4) ? 4 : 2;
                i7 = i3 | i12;
            } else {
                l4 = l2;
            }
            i7 = i3 | i12;
        } else {
            l4 = l2;
            i7 = i3;
        }
        if ((i3 & 48) == 0) {
            i7 |= ((i4 & 2048) == 0 && c0814p2.c(f)) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            i7 |= ((i4 & 4096) == 0 && c0814p2.c(f2)) ? 256 : 128;
        }
        int i13 = i7;
        if ((i9 & 306783379) == 306783378 && (i13 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            f6 = f;
            f7 = f2;
            c0814p = c0814p2;
            l9 = l3;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                if ((i4 & 256) != 0) {
                    l5 = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k;
                    i9 &= -234881025;
                } else {
                    l5 = l3;
                }
                int i14 = i11 != 0 ? 1 : i6;
                if ((i4 & 1024) != 0) {
                    l6 = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k;
                    i13 &= -15;
                } else {
                    l6 = l4;
                }
                if ((i4 & 2048) != 0) {
                    f3 = com.quizlet.themes.m.s0;
                    i13 &= -113;
                } else {
                    f3 = f;
                }
                if ((i4 & 4096) != 0) {
                    com.quizlet.themes.m.g.h();
                    i13 &= -897;
                    l7 = l5;
                    i8 = i14;
                    l8 = l6;
                    f5 = f3;
                    f4 = com.quizlet.ui.resources.designsystem.generated.h.g;
                } else {
                    f4 = f2;
                    l7 = l5;
                    i8 = i14;
                    l8 = l6;
                    f5 = f3;
                }
            } else {
                c0814p2.Q();
                if ((i4 & 256) != 0) {
                    i9 &= -234881025;
                }
                if ((i4 & 1024) != 0) {
                    i13 &= -15;
                }
                if ((i4 & 2048) != 0) {
                    i13 &= -113;
                }
                if ((i4 & 4096) != 0) {
                    i13 &= -897;
                }
                f5 = f;
                f4 = f2;
                l7 = l3;
                i8 = i6;
                l8 = l4;
            }
            c0814p2.q();
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(kVar.a, c0814p2, 0);
            c0814p2.X(-1056794038);
            String strD = AbstractC3106b5.d(c0814p2, kVar.c);
            c0814p2.p(false);
            int i15 = i9 << 6;
            int i16 = i9 << 3;
            int i17 = i13 << 6;
            c0814p = c0814p2;
            B5.a(bVarA, kVar.b, str, strD, qVar2, z3, dVar2, z2, null, function0, l7, i8, l8, f5, f4, c0814p, (58240 & i15) | (458752 & i16) | (3670016 & i16) | (i16 & 29360128) | (i15 & 1879048192), ((i9 >> 24) & 126) | (i17 & 896) | (i17 & 7168) | (i17 & 57344));
            l9 = l7;
            i6 = i8;
            l4 = l8;
            f6 = f5;
            f7 = f4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.listitems.p
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int iH2 = C0776c.H(i3);
                    float f8 = f7;
                    int i18 = i4;
                    C5.a(str, kVar, qVar, z, dVar, z2, function0, l9, i6, l4, f6, f8, (InterfaceC0806l) obj, iH, iH2, i18);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00db  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:93:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.ui.models.content.listitem.a r24, androidx.compose.ui.n r25, boolean r26, androidx.compose.runtime.internal.d r27, boolean r28, kotlin.jvm.functions.Function0 r29, androidx.compose.runtime.InterfaceC0806l r30, int r31, int r32) {
        /*
            Method dump skipped, instructions count: 317
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.b(com.quizlet.ui.models.content.listitem.a, androidx.compose.ui.n, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(final androidx.compose.ui.graphics.painter.b icon, final String title, final String metadata, final long j, final Function0 onClick, final String str, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        long j2;
        C0814p c0814p;
        int i3 = 2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(428942764);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(icon) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(title) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(metadata) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            j2 = j;
            i2 |= c0814p2.e(j2) ? 2048 : 1024;
        } else {
            j2 = j;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(onClick) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.f(nVar) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.f(str) ? 1048576 : 524288;
        }
        int i4 = i2;
        if ((599187 & i4) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-1880547989);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            com.quizlet.themes.b bVar = (com.quizlet.themes.b) c0814p2.j(b);
            float f = com.quizlet.assembly.compose.listitems.A.a;
            long jG = bVar.b.g();
            com.quizlet.ui.resources.designsystem.generated.p pVar = bVar.b;
            long jE = pVar.e();
            long jF = pVar.f();
            long jF2 = pVar.f();
            long jB = pVar.b();
            long jB2 = pVar.b();
            long jB3 = pVar.b();
            c0814p2.p(false);
            c0814p = c0814p2;
            D5.a(androidx.compose.runtime.internal.e.e(1568930573, new com.quizlet.assembly.compose.links.e(icon, title, j2, 2), c0814p2), androidx.compose.runtime.internal.e.e(528638734, new com.quizlet.assembly.compose.input.l(1, title, str), c0814p2), androidx.compose.runtime.internal.e.e(-511653105, new com.quizlet.assembly.compose.input.i(metadata, i3), c0814p2), nVar, false, null, false, new com.quizlet.assembly.compose.listitems.z(((com.quizlet.themes.b) c0814p2.j(b)).Z0, jE, jF, jF2, jG, jB, jB2, jB3), null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, onClick, c0814p, ((i4 >> 6) & 7168) | 438, (i4 >> 9) & ContentType.LONG_FORM_ON_DEMAND, 1904);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.listitems.q
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function0 function0 = onClick;
                    String str2 = str;
                    C5.c(icon, title, metadata, j, function0, str2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(com.quizlet.ui.models.content.listitem.c r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.d(com.quizlet.ui.models.content.listitem.c, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x012a A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0279  */
    /* JADX WARN: Removed duplicated region for block: B:172:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x00ff  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(com.quizlet.ui.models.content.listitem.c r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.runtime.internal.d r33, boolean r34, kotlin.jvm.functions.Function0 r35, androidx.compose.ui.text.L r36, int r37, androidx.compose.ui.text.L r38, float r39, float r40, androidx.compose.runtime.InterfaceC0806l r41, int r42, int r43) {
        /*
            Method dump skipped, instructions count: 646
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.e(com.quizlet.ui.models.content.listitem.c, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:104:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x015d  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0166  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(com.quizlet.ui.models.content.listitem.d r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 446
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.f(com.quizlet.ui.models.content.listitem.d, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x012b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x013e A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01c5  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x01cc  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01f0  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0201  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0210  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x021e  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x022b  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x02a3  */
    /* JADX WARN: Removed duplicated region for block: B:184:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0100  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(com.quizlet.ui.models.content.listitem.d r32, androidx.compose.ui.q r33, boolean r34, androidx.compose.runtime.internal.d r35, boolean r36, kotlin.jvm.functions.Function0 r37, androidx.compose.ui.text.L r38, int r39, androidx.compose.ui.text.L r40, float r41, float r42, float r43, androidx.compose.runtime.InterfaceC0806l r44, int r45, int r46) {
        /*
            Method dump skipped, instructions count: 695
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.g(com.quizlet.ui.models.content.listitem.d, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, float, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void h(com.quizlet.ui.models.content.listitem.e r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.h(com.quizlet.ui.models.content.listitem.e, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x012a A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0279  */
    /* JADX WARN: Removed duplicated region for block: B:172:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x00ff  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void i(com.quizlet.ui.models.content.listitem.e r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.runtime.internal.d r33, boolean r34, kotlin.jvm.functions.Function0 r35, androidx.compose.ui.text.L r36, int r37, androidx.compose.ui.text.L r38, float r39, float r40, androidx.compose.runtime.InterfaceC0806l r41, int r42, int r43) {
        /*
            Method dump skipped, instructions count: 646
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.i(com.quizlet.ui.models.content.listitem.e, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, androidx.compose.runtime.l, int, int):void");
    }

    public static final void j(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1838422343);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            B5.b(com.quizlet.assembly.compose.listitems.y.a, com.quizlet.assembly.compose.listitems.y.b, com.quizlet.assembly.compose.listitems.y.c, androidx.compose.ui.platform.N.G(nVar, "AssemblyContentListItemTypesLoadingShimmer"), false, null, false, null, null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, c0814p, 438, 0, 4080);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 1, qVar2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void k(com.quizlet.ui.models.content.listitem.f r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 432
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.k(com.quizlet.ui.models.content.listitem.f, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x012b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x013e A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01c5  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x01cc  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01f0  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0201  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0210  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x021e  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:180:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0100  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void l(com.quizlet.ui.models.content.listitem.f r32, androidx.compose.ui.q r33, boolean r34, androidx.compose.runtime.internal.d r35, boolean r36, kotlin.jvm.functions.Function0 r37, androidx.compose.ui.text.L r38, int r39, androidx.compose.ui.text.L r40, float r41, float r42, float r43, androidx.compose.runtime.InterfaceC0806l r44, int r45, int r46) {
        /*
            Method dump skipped, instructions count: 688
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.l(com.quizlet.ui.models.content.listitem.f, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, float, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0106  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:69:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m(final com.quizlet.ui.models.content.listitem.g r18, androidx.compose.ui.n r19, boolean r20, java.lang.Integer r21, kotlin.jvm.functions.Function0 r22, boolean r23, kotlin.jvm.functions.Function0 r24, androidx.compose.runtime.InterfaceC0806l r25, final int r26, final int r27) {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.m(com.quizlet.ui.models.content.listitem.g, androidx.compose.ui.n, boolean, java.lang.Integer, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x012a A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0279  */
    /* JADX WARN: Removed duplicated region for block: B:172:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x00ff  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void n(com.quizlet.ui.models.content.listitem.g r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.runtime.internal.d r33, boolean r34, kotlin.jvm.functions.Function0 r35, androidx.compose.ui.text.L r36, int r37, androidx.compose.ui.text.L r38, float r39, float r40, androidx.compose.runtime.InterfaceC0806l r41, int r42, int r43) {
        /*
            Method dump skipped, instructions count: 646
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.n(com.quizlet.ui.models.content.listitem.g, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void o(com.quizlet.ui.models.content.listitem.p r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.o(com.quizlet.ui.models.content.listitem.p, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0127 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01b7  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01bc  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x01da  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01f1  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x01f7  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x020d  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x02b6  */
    /* JADX WARN: Removed duplicated region for block: B:174:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x00fc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void p(com.quizlet.ui.models.content.listitem.p r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.runtime.internal.d r33, boolean r34, kotlin.jvm.functions.Function0 r35, androidx.compose.ui.text.L r36, int r37, androidx.compose.ui.text.L r38, float r39, float r40, androidx.compose.runtime.InterfaceC0806l r41, int r42, int r43) {
        /*
            Method dump skipped, instructions count: 705
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.p(com.quizlet.ui.models.content.listitem.p, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void q(com.quizlet.ui.models.content.listitem.q r19, androidx.compose.ui.q r20, boolean r21, java.lang.Integer r22, java.lang.String r23, kotlin.jvm.functions.Function0 r24, boolean r25, kotlin.jvm.functions.Function0 r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.q(com.quizlet.ui.models.content.listitem.q, androidx.compose.ui.q, boolean, java.lang.Integer, java.lang.String, kotlin.jvm.functions.Function0, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0127 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01ad  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:155:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x01db  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x01e1  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x01ed  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x028d  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x030d  */
    /* JADX WARN: Removed duplicated region for block: B:178:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x00fc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void r(com.quizlet.ui.models.content.listitem.q r30, androidx.compose.ui.q r31, boolean r32, androidx.compose.runtime.internal.d r33, boolean r34, kotlin.jvm.functions.Function0 r35, androidx.compose.ui.text.L r36, int r37, androidx.compose.ui.text.L r38, float r39, float r40, androidx.compose.runtime.InterfaceC0806l r41, int r42, int r43) {
        /*
            Method dump skipped, instructions count: 794
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.C5.r(com.quizlet.ui.models.content.listitem.q, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, kotlin.jvm.functions.Function0, androidx.compose.ui.text.L, int, androidx.compose.ui.text.L, float, float, androidx.compose.runtime.l, int, int):void");
    }

    public static final String s(com.quizlet.ui.models.content.listitem.b bVar, InterfaceC0806l interfaceC0806l) {
        String strC;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(100345075);
        if (bVar.a()) {
            strC = com.google.android.gms.measurement.internal.Z.h(c0814p, 528937595, R.string.by_you, c0814p, false);
        } else if (bVar.b() != null) {
            c0814p.X(529012708);
            String strB = bVar.b();
            if (strB == null) {
                strB = "";
            }
            strC = AbstractC3106b5.c(R.string.by_creator, new Object[]{strB}, c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(529083419);
            c0814p.p(false);
            strC = null;
        }
        c0814p.p(false);
        return strC;
    }
}
