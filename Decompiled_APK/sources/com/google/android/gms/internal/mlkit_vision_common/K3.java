package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
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
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_common.K3;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class K3 {
    public static final void a(final long j, androidx.compose.ui.q qVar, final Boolean bool, final boolean z, final String str, final String str2, final Function2 function2, final kotlin.jvm.functions.d dVar, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1132747337);
        int i2 = i | (c0814p2.e(j) ? 4 : 2) | (c0814p2.f(bool) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.f(str) ? 16384 : 8192) | (c0814p2.f(str2) ? 131072 : 65536) | (c0814p2.h(function2) ? 1048576 : 524288) | (c0814p2.h(dVar) ? 8388608 : 4194304);
        if ((4793491 & i2) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            int i3 = i2 >> 3;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            qVar2 = qVar;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar2);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            int i5 = i2 & 14;
            int i6 = i2 >> 6;
            c0814p = c0814p2;
            b(j, z, str, str2, null, dVar, c0814p, (i6 & ContentType.LONG_FORM_ON_DEMAND) | i5 | (i6 & 896) | (i6 & 7168) | (i6 & 458752));
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.o();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, com.quizlet.ui.resources.designsystem.generated.j.p));
            c0814p.X(-1357633236);
            if (bool != null) {
                c(j, bool.booleanValue(), null, function2, c0814p, i5 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 9) & 7168));
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final androidx.compose.ui.q qVar3 = qVar2;
            c0813o0R.d = new Function2(j, qVar3, bool, z, str, str2, function2, dVar, i) { // from class: com.quizlet.features.termlist.ui.composables.c
                public final /* synthetic */ long a;
                public final /* synthetic */ q b;
                public final /* synthetic */ Boolean c;
                public final /* synthetic */ boolean d;
                public final /* synthetic */ String e;
                public final /* synthetic */ String f;
                public final /* synthetic */ Function2 g;
                public final /* synthetic */ kotlin.jvm.functions.d h;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(49);
                    Function2 function22 = this.g;
                    kotlin.jvm.functions.d dVar2 = this.h;
                    K3.a(this.a, this.b, this.c, this.d, this.e, this.f, function22, dVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(final long j, final boolean z, String str, String str2, androidx.compose.ui.q qVar, kotlin.jvm.functions.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        String str3;
        String str4;
        kotlin.jvm.functions.d dVar2;
        boolean z2;
        long jS;
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-475229219);
        if ((i & 6) == 0) {
            i2 = (c0814p2.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            str3 = str;
            i2 |= c0814p2.f(str3) ? 256 : 128;
        } else {
            str3 = str;
        }
        if ((i & 3072) == 0) {
            str4 = str2;
            i2 |= c0814p2.f(str4) ? 2048 : 1024;
        } else {
            str4 = str2;
        }
        int i3 = i2 | 24576;
        if ((196608 & i) == 0) {
            dVar2 = dVar;
            i3 |= c0814p2.h(dVar2) ? 131072 : 65536;
        } else {
            dVar2 = dVar;
        }
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "term_audio_icon");
            c0814p2.X(197101786);
            boolean z3 = ((i3 & 14) == 4) | ((458752 & i3) == 131072) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 896) == 256) | ((i3 & 7168) == 2048);
            Object objI = c0814p2.I();
            if (z3 || objI == v) {
                z2 = false;
                final String str5 = str4;
                final kotlin.jvm.functions.d dVar3 = dVar2;
                final String str6 = str3;
                Function0 function0 = new Function0() { // from class: com.quizlet.features.termlist.ui.composables.e
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        dVar3.invoke(Long.valueOf(j), Boolean.valueOf(z), str6, str5);
                        return Unit.a;
                    }
                };
                c0814p2.i0(function0);
                objI = function0;
            } else {
                z2 = false;
            }
            c0814p2.p(z2);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarG, z2, null, (Function0) objI, 7);
            ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarN = com.quizlet.ui.resources.icons.d.n(c0814p2);
            String strD = AbstractC3106b5.d(c0814p2, R.string.icon_label_listen);
            if (z) {
                c0814p2.X(197109958);
                jS = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).G();
            } else {
                c0814p2.X(197111364);
                jS = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).s();
            }
            c0814p2.p(z2);
            c0814p = c0814p2;
            androidx.compose.material3.D1.a(bVarN, strD, qVarL, jS, c0814p, 0, 0);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.termlist.ui.composables.f(j, z, str, str2, qVar2, dVar, i);
        }
    }

    public static final void c(final long j, final boolean z, androidx.compose.ui.q qVar, final Function2 function2, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        InterfaceC0773a0 interfaceC0773a0;
        int i3;
        long jG;
        final androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-260574081);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        int i4 = i2 | 384;
        if ((i & 3072) == 0) {
            i4 |= c0814p.h(function2) ? 2048 : 1024;
        }
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(1441969559);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z(Boolean.valueOf(z));
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            boolean zBooleanValue = ((Boolean) interfaceC0773a02.getValue()).booleanValue();
            c0814p.X(-1646115343);
            c0814p.X(1228148699);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = C0776c.w(zBooleanValue ? R.string.icon_label_star : R.string.icon_label_no_star);
                c0814p.i0(objI2);
            }
            androidx.compose.runtime.H0 h0 = (androidx.compose.runtime.H0) objI2;
            c0814p.p(false);
            c0814p.p(false);
            Boolean boolValueOf = Boolean.valueOf(z);
            c0814p.X(1441974100);
            boolean z2 = (i4 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == v) {
                objI3 = new com.quizlet.features.termlist.ui.composables.g(z, interfaceC0773a02, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, boolValueOf, (Function2) objI3);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "term_star_icon");
            c0814p.X(1441978609);
            boolean z3 = ((i4 & 7168) == 2048) | ((i4 & 14) == 4);
            Object objI4 = c0814p.I();
            if (z3 || objI4 == v) {
                interfaceC0773a0 = interfaceC0773a02;
                com.braze.H h = new com.braze.H(function2, j, interfaceC0773a0, 7);
                c0814p.i0(h);
                objI4 = h;
            } else {
                interfaceC0773a0 = interfaceC0773a02;
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarG, false, null, (Function0) objI4, 7);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                c0814p.X(1441983515);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(1342053774);
                i3 = R.drawable.ic_sys_star_filled;
            } else {
                c0814p.X(1441984885);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(1882035022);
                i3 = R.drawable.ic_sys_star;
            }
            androidx.compose.ui.graphics.painter.b bVarD = com.google.android.gms.measurement.internal.Z.d(i3, c0814p, 0, false, false);
            String strD = AbstractC3106b5.d(c0814p, ((Number) h0.getValue()).intValue());
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                c0814p.X(1441988738);
                jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).G();
            } else {
                c0814p.X(1441990141);
                jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).l;
            }
            c0814p.p(false);
            androidx.compose.material3.D1.a(bVarD, strD, qVarL, jG, c0814p, 0, 0);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.termlist.ui.composables.d
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    q qVar3 = qVar2;
                    Function2 function22 = function2;
                    K3.c(j, z, qVar3, function22, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static int d(Object obj, Object obj2, int i, Object obj3, int[] iArr, Object[] objArr, Object[] objArr2) {
        int i2;
        int i3;
        int iB = L3.b(obj);
        int i4 = iB & i;
        int iE = e(i4, obj3);
        if (iE != 0) {
            int i5 = ~i;
            int i6 = iB & i5;
            int i7 = -1;
            while (true) {
                i2 = iE - 1;
                int i8 = iArr[i2];
                i3 = i8 & i;
                if ((i8 & i5) != i6 || !H3.b(obj, objArr[i2]) || (objArr2 != null && !H3.b(obj2, objArr2[i2]))) {
                    if (i3 == 0) {
                        break;
                    }
                    i7 = i2;
                    iE = i3;
                } else {
                    break;
                }
            }
            if (i7 == -1) {
                g(i4, i3, obj3);
                return i2;
            }
            iArr[i7] = (iArr[i7] & i5) | (i3 & i);
            return i2;
        }
        return -1;
    }

    public static int e(int i, Object obj) {
        return obj instanceof byte[] ? ((byte[]) obj)[i] & 255 : obj instanceof short[] ? (char) ((short[]) obj)[i] : ((int[]) obj)[i];
    }

    public static Object f(int i) {
        if (i < 2 || i > 1073741824 || Integer.highestOneBit(i) != i) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "must be power of 2 between 2^1 and 2^30: "));
        }
        return i <= 256 ? new byte[i] : i <= 65536 ? new short[i] : new int[i];
    }

    public static void g(int i, int i2, Object obj) {
        if (obj instanceof byte[]) {
            ((byte[]) obj)[i] = (byte) i2;
        } else if (obj instanceof short[]) {
            ((short[]) obj)[i] = (short) i2;
        } else {
            ((int[]) obj)[i] = i2;
        }
    }
}
