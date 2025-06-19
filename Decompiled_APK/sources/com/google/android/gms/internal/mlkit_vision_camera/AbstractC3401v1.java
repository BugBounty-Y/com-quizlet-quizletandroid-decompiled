package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.v1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3401v1 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String str, androidx.glance.p pVar, androidx.glance.text.g gVar, int i, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        int i4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-192911377);
        if ((i2 & 6) == 0) {
            i4 = (c0814p.f(str) ? 4 : 2) | i2;
        } else {
            i4 = i2;
        }
        int i5 = i3 & 2;
        if (i5 != 0) {
            i4 |= 48;
        } else if ((i2 & 48) == 0) {
            i4 |= c0814p.f(pVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p.f(gVar) ? 256 : 128;
        }
        int i6 = i3 & 8;
        if (i6 != 0) {
            i4 |= 3072;
        } else if ((i2 & 3072) == 0) {
            i4 |= c0814p.d(i) ? 2048 : 1024;
        }
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                if (i5 != 0) {
                    pVar = androidx.glance.n.a;
                }
                if (i6 != 0) {
                    i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                }
            } else {
                c0814p.Q();
            }
            c0814p.q();
            androidx.glance.text.d dVar = androidx.glance.text.d.a;
            c0814p.Y(-1115894518);
            c0814p.Y(1886828752);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(new androidx.compose.ui.input.nestedscroll.b(dVar));
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, str, androidx.glance.text.e.b);
            C0776c.E(c0814p, pVar, androidx.glance.text.e.c);
            C0776c.E(c0814p, gVar, androidx.glance.text.e.d);
            androidx.glance.text.e eVar = androidx.glance.text.e.e;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i))) {
                c0814p.i0(Integer.valueOf(i));
                c0814p.b(Integer.valueOf(i), eVar);
            }
            androidx.compose.ui.node.B.s(c0814p, true, false, false);
        }
        androidx.glance.p pVar2 = pVar;
        int i7 = i;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.glance.text.f(str, pVar2, gVar, i7, i2, i3);
        }
    }

    public static final long b(long j) {
        if (j < 0) {
            kotlin.time.b.b.getClass();
            return kotlin.time.b.d;
        }
        kotlin.time.b.b.getClass();
        return kotlin.time.b.c;
    }

    public static final long c(long j, long j2, kotlin.time.d dVar) {
        long j3 = j - j2;
        if (((j3 ^ j) & (~(j3 ^ j2))) >= 0) {
            return AbstractC3397u1.g(j3, dVar);
        }
        kotlin.time.d dVar2 = kotlin.time.d.c;
        if (dVar.compareTo(dVar2) >= 0) {
            return kotlin.time.b.k(b(j3));
        }
        long jB = kotlin.time.e.b(1L, dVar2, dVar);
        long j4 = (j / jB) - (j2 / jB);
        long j5 = (j % jB) - (j2 % jB);
        kotlin.time.a aVar = kotlin.time.b.b;
        return kotlin.time.b.h(AbstractC3397u1.g(j4, dVar2), AbstractC3397u1.g(j5, dVar));
    }
}
