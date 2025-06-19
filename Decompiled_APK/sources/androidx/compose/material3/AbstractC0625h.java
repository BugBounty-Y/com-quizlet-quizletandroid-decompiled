package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.W5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0625h {
    public static final float a = 280;
    public static final float b = 560;
    public static final float c = 8;
    public static final float d = 12;
    public static final androidx.compose.foundation.layout.A0 e;
    public static final androidx.compose.foundation.layout.A0 f;
    public static final androidx.compose.foundation.layout.A0 g;

    static {
        float f2 = 24;
        e = new androidx.compose.foundation.layout.A0(f2, f2, f2, f2);
        float f3 = 16;
        AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, 7);
        f = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, 7);
        g = AbstractC0382e.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7);
    }

    public static final void a(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.ui.graphics.V v, long j, float f2, long j2, long j3, long j4, long j5, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1522575799);
        int i2 = i | 48 | (c0814p.h(null) ? 256 : 128) | (c0814p.h(dVar2) ? 2048 : 1024) | (c0814p.h(dVar3) ? 16384 : 8192) | (c0814p.f(v) ? 131072 : 65536) | (c0814p.e(j) ? 1048576 : 524288) | (c0814p.c(f2) ? 8388608 : 4194304) | (c0814p.e(j2) ? 67108864 : 33554432) | (c0814p.e(j3) ? 536870912 : 268435456);
        int i3 = (c0814p.e(j4) ? (char) 4 : (char) 2) | (c0814p.e(j5) ? ' ' : (char) 16);
        if ((i2 & 306783379) == 306783378 && (i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            int i4 = i2 >> 12;
            AbstractC0594b4.a(nVar3, v, j, 0L, f2, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(-2126308228, new C0589b(dVar2, dVar3, j3, j4, j5, j2, dVar), c0814p), c0814p, (i4 & 896) | (i4 & ContentType.LONG_FORM_ON_DEMAND) | 12582918 | ((i2 >> 9) & 57344), 104);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0595c(dVar, nVar2, dVar2, dVar3, v, j, f2, j2, j3, j4, j5, i);
        }
    }

    public static final void b(androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(586821353);
        if ((i & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new C0601d(0);
                c0814p.i0(objI);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.animation.d0.w(6, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.layout.W(dVar, i, 6);
        }
    }

    public static final void c(Function0 function0, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.ui.graphics.V v, long j, long j2, long j3, long j4, float f2, androidx.compose.ui.window.r rVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.runtime.internal.d dVar5;
        androidx.compose.runtime.internal.d dVar6;
        int i4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-919826268);
        if ((i & 6) == 0) {
            i3 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            dVar5 = dVar;
            i3 |= c0814p.h(dVar5) ? 32 : 16;
        } else {
            dVar5 = dVar;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            dVar6 = dVar2;
            i3 |= c0814p.h(dVar6) ? 2048 : 1024;
        } else {
            dVar6 = dVar2;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(null) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.h(dVar3) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p.h(dVar4) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p.f(v) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p.e(j) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.e(j2) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.e(j3) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.e(j4) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p.c(f2) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p.f(rVar) ? 2048 : 1024;
        }
        int i5 = i4;
        if ((i3 & 306783379) == 306783378 && (i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            d(function0, qVar, rVar, androidx.compose.runtime.internal.e.e(-1852840226, new C0613f(dVar3, dVar4, v, j, f2, j2, j3, j4, dVar6, dVar5), c0814p), c0814p, (i3 & 14) | 3072 | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i5 >> 3) & 896));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0619g(function0, dVar, qVar, dVar2, dVar3, dVar4, v, j, j2, j3, j4, f2, rVar, i, i2);
        }
    }

    public static final void d(Function0 function0, androidx.compose.ui.q qVar, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1922902937);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(rVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            W5.a(function0, rVar, androidx.compose.runtime.internal.e.e(905289008, new androidx.compose.foundation.text.selection.e0(qVar, dVar), c0814p), c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 14) | 384);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.b(function0, qVar, rVar, dVar, i);
        }
    }
}
