package androidx.compose.material3;

import androidx.compose.animation.C0285l;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.t3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0725t3 {
    public static final float a = 16;

    /* JADX WARN: Removed duplicated region for block: B:100:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x015a  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x015d  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0167  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01cf A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x01f9 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x025d  */
    /* JADX WARN: Removed duplicated region for block: B:145:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x014a  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0151  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.q r30, androidx.compose.runtime.internal.d r31, androidx.compose.runtime.internal.d r32, androidx.compose.runtime.internal.d r33, androidx.compose.runtime.internal.d r34, int r35, long r36, long r38, androidx.compose.foundation.layout.R0 r40, androidx.compose.runtime.internal.d r41, androidx.compose.runtime.InterfaceC0806l r42, int r43, int r44) {
        /*
            Method dump skipped, instructions count: 615
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.AbstractC0725t3.a(androidx.compose.ui.q, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, int, long, long, androidx.compose.foundation.layout.R0, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(int i, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.foundation.layout.R0 r0, androidx.compose.runtime.internal.d dVar5, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        androidx.compose.runtime.internal.d dVar6;
        androidx.compose.foundation.layout.R0 r02;
        androidx.compose.runtime.internal.d dVar7;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-975511942);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(dVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            dVar6 = dVar2;
            i3 |= c0814p.h(dVar6) ? 256 : 128;
        } else {
            dVar6 = dVar2;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(dVar3) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p.h(dVar4) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            r02 = r0;
            i3 |= c0814p.f(r02) ? 131072 : 65536;
        } else {
            r02 = r0;
        }
        if ((1572864 & i2) == 0) {
            dVar7 = dVar5;
            i3 |= c0814p.h(dVar7) ? 1048576 : 524288;
        } else {
            dVar7 = dVar5;
        }
        if ((i3 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean z = ((i3 & 896) == 256) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 7168) == 2048) | ((458752 & i3) == 131072) | ((57344 & i3) == 16384) | ((i3 & 14) == 4) | ((3670016 & i3) == 1048576);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                C0285l c0285l = new C0285l(dVar, dVar3, dVar4, i, r02, dVar7, dVar6);
                c0814p.i0(c0285l);
                objI = c0285l;
            }
            AbstractC0897s.c(null, (Function2) objI, c0814p, 0, 1);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0719s3(i, dVar, dVar2, dVar3, dVar4, r0, dVar5, i2);
        }
    }
}
