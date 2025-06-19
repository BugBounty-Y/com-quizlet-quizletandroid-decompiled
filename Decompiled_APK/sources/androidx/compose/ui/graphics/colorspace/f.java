package androidx.compose.ui.graphics.colorspace;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f extends g {
    public final q e;
    public final q f;
    public final float[] g;

    public f(q qVar, q qVar2) {
        float[] fArrH;
        super(qVar2, qVar, qVar2, null);
        this.e = qVar;
        this.f = qVar2;
        s sVar = qVar2.d;
        s sVar2 = qVar.d;
        boolean zD = j.d(sVar2, sVar);
        float[] fArrH2 = qVar.i;
        float[] fArrG = qVar2.j;
        if (zD) {
            fArrH = j.h(fArrG, fArrH2);
        } else {
            float[] fArrA = sVar2.a();
            s sVar3 = qVar2.d;
            float[] fArrA2 = sVar3.a();
            s sVar4 = j.b;
            boolean zD2 = j.d(sVar2, sVar4);
            float[] fArr = j.e;
            float[] fArr2 = a.b.a;
            if (!zD2) {
                float[] fArrCopyOf = Arrays.copyOf(fArr, 3);
                Intrinsics.checkNotNullExpressionValue(fArrCopyOf, "copyOf(this, size)");
                fArrH2 = j.h(j.c(fArr2, fArrA, fArrCopyOf), fArrH2);
            }
            if (!j.d(sVar3, sVar4)) {
                float[] fArrCopyOf2 = Arrays.copyOf(fArr, 3);
                Intrinsics.checkNotNullExpressionValue(fArrCopyOf2, "copyOf(this, size)");
                fArrG = j.g(j.h(j.c(fArr2, fArrA2, fArrCopyOf2), qVar2.i));
            }
            fArrH = j.h(fArrG, fArrH2);
        }
        this.g = fArrH;
    }

    @Override // androidx.compose.ui.graphics.colorspace.g
    public final long a(long j) {
        float fH = C0861v.h(j);
        float fG = C0861v.g(j);
        float fE = C0861v.e(j);
        float fD = C0861v.d(j);
        m mVar = this.e.p;
        float fD2 = (float) mVar.d(fH);
        float fD3 = (float) mVar.d(fG);
        float fD4 = (float) mVar.d(fE);
        float[] fArr = this.g;
        float f = (fArr[6] * fD4) + (fArr[3] * fD3) + (fArr[0] * fD2);
        float f2 = (fArr[7] * fD4) + (fArr[4] * fD3) + (fArr[1] * fD2);
        float f3 = (fArr[8] * fD4) + (fArr[5] * fD3) + (fArr[2] * fD2);
        q qVar = this.f;
        float fD5 = (float) qVar.m.d(f);
        double d = f2;
        m mVar2 = qVar.m;
        return F.b(fD5, (float) mVar2.d(d), (float) mVar2.d(f3), fD, qVar);
    }
}
