package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0274x;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.material3.y4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0765y4 {
    public static final float a = 90;
    public static final androidx.compose.animation.core.K0 b;
    public static final androidx.compose.animation.core.K0 c;

    static {
        C0274x c0274x = androidx.compose.animation.core.C.a;
        b = AbstractC0240f.r(250, 0, c0274x, 2);
        c = AbstractC0240f.r(250, 0, c0274x, 2);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:88:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r25, androidx.compose.ui.q r26, long r27, long r29, float r31, androidx.compose.runtime.internal.d r32, androidx.compose.runtime.internal.d r33, androidx.compose.runtime.internal.d r34, androidx.compose.runtime.InterfaceC0806l r35, int r36, int r37) {
        /*
            Method dump skipped, instructions count: 316
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.AbstractC0765y4.a(int, androidx.compose.ui.q, long, long, float, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(int i, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, long j, long j2, float f, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.foundation.N0 n0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-955409947);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.h(dVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.e(j) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.e(j2) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p2.c(f) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i3 |= c0814p2.h(dVar2) ? 1048576 : 524288;
        }
        if ((i2 & 12582912) == 0) {
            i3 |= c0814p2.h(dVar3) ? 8388608 : 4194304;
        }
        if ((100663296 & i2) == 0) {
            i3 |= c0814p2.f(n0) ? 67108864 : 33554432;
        }
        if ((38347923 & i3) == 38347922 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            int i4 = ((i3 >> 6) & 14) | 12582912;
            int i5 = i3 >> 3;
            c0814p = c0814p2;
            AbstractC0594b4.a(qVar, null, j, j2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(-1572959552, new C0753w4(n0, f, dVar3, dVar2, dVar, i), c0814p2), c0814p, i4 | (i5 & 896) | (i5 & 7168), 114);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0759x4(i, dVar, qVar, j, j2, f, dVar2, dVar3, n0, i2);
        }
    }
}
