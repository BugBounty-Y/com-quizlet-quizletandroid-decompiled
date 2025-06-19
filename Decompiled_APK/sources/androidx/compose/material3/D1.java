package androidx.compose.material3;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.vector.AbstractC0863b;
import androidx.compose.ui.graphics.vector.C0867f;
import com.comscore.streaming.ContentType;

/* loaded from: classes.dex */
public abstract class D1 {
    public static final androidx.compose.ui.q a = androidx.compose.foundation.layout.K0.k(androidx.compose.ui.n.b, androidx.compose.material3.tokens.m.a);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:101:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:103:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00c6 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0134  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x014c  */
    /* JADX WARN: Type inference failed for: r3v16 */
    /* JADX WARN: Type inference failed for: r3v17, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v20 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.graphics.painter.b r16, java.lang.String r17, androidx.compose.ui.q r18, long r19, androidx.compose.runtime.InterfaceC0806l r21, int r22, int r23) {
        /*
            Method dump skipped, instructions count: 378
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.D1.a(androidx.compose.ui.graphics.painter.b, java.lang.String, androidx.compose.ui.q, long, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(C0867f c0867f, String str, androidx.compose.ui.q qVar, long j, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        String str2;
        androidx.compose.ui.q qVar2;
        long j2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-126890956);
        int i4 = (c0814p.f(c0867f) ? 4 : 2) | i | (c0814p.f(str) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
        } else {
            i3 = i4 | (c0814p.f(qVar) ? 256 : 128);
        }
        int i6 = i3 | 1024;
        if ((i6 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            j2 = j;
            qVar2 = qVar;
            str2 = str;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if (i5 != 0) {
                    qVar = androidx.compose.ui.n.b;
                }
                j = ((C0861v) c0814p.j(AbstractC0669k0.a)).a;
            } else {
                c0814p.Q();
            }
            int i7 = i6 & (-7169);
            androidx.compose.ui.q qVar3 = qVar;
            long j3 = j;
            c0814p.q();
            a(AbstractC0863b.c(c0867f, c0814p), str, qVar3, j3, c0814p, (i7 & ContentType.LONG_FORM_ON_DEMAND) | 8 | (i7 & 896), 0);
            str2 = str;
            qVar2 = qVar3;
            j2 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material.B(c0867f, str2, qVar2, j2, i, i2);
        }
    }
}
