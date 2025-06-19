package androidx.compose.foundation;

import android.text.Layout;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.text.C0982b;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0552u extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0552u(long j, float[] fArr, kotlin.jvm.internal.H h, kotlin.jvm.internal.G g) {
        super(1);
        this.a = 2;
        this.b = j;
        this.c = fArr;
        this.d = h;
        this.e = g;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0982b c0982b;
        long j;
        boolean z;
        float fA;
        float fA2;
        switch (this.a) {
            case 0:
                androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
                g.b();
                androidx.compose.ui.geometry.c cVar = (androidx.compose.ui.geometry.c) this.c;
                kotlin.jvm.internal.J j2 = (kotlin.jvm.internal.J) this.d;
                long j3 = this.b;
                C0853m c0853m = (C0853m) this.e;
                androidx.compose.ui.graphics.drawscope.b bVar = g.a;
                androidx.appcompat.app.L l = (androidx.appcompat.app.L) bVar.b.b;
                float f = cVar.a;
                float f2 = cVar.b;
                l.S(f, f2);
                try {
                    androidx.compose.ui.graphics.drawscope.d.P(g, (C0848h) j2.a, j3, 0L, DefinitionKt.NO_Float_VALUE, c0853m, 0, 890);
                    ((androidx.appcompat.app.L) bVar.b.b).S(-f, -f2);
                    return Unit.a;
                } catch (Throwable th) {
                    ((androidx.appcompat.app.L) bVar.b.b).S(-f, -f2);
                    throw th;
                }
            case 1:
                androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
                float fFloatValue = ((Number) ((Function0) this.c).invoke()).floatValue();
                float fMax = (Math.max(Math.min(1.0f, fFloatValue) - 0.4f, DefinitionKt.NO_Float_VALUE) * 5) / 3;
                float fB = kotlin.ranges.l.b(Math.abs(fFloatValue) - 1.0f, DefinitionKt.NO_Float_VALUE, 2.0f);
                float fPow = (((0.4f * fMax) - 0.25f) + (fB - (((float) Math.pow(fB, 2)) / 4))) * 0.5f;
                float f3 = 360;
                float f4 = fPow * f3;
                float f5 = ((0.8f * fMax) + fPow) * f3;
                androidx.compose.animation.f0 f0Var = new androidx.compose.animation.f0(fPow, f4, f5, Math.min(1.0f, fMax));
                float fFloatValue2 = ((Number) ((W0) this.d).getValue()).floatValue();
                long j4 = this.b;
                androidx.compose.ui.graphics.O o = (androidx.compose.ui.graphics.O) this.e;
                long jO0 = dVar.o0();
                com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
                long jR = cVarE0.r();
                cVarE0.o().e();
                try {
                    ((androidx.appcompat.app.L) cVarE0.b).O(jO0, fPow);
                    float fC0 = dVar.c0(androidx.compose.material3.pulltorefresh.g.b);
                    float f6 = androidx.compose.material3.pulltorefresh.g.a;
                    float fC02 = (dVar.c0(f6) / 2.0f) + fC0;
                    long jC = T4.c(dVar.g());
                    float fD = androidx.compose.ui.geometry.b.d(jC) - fC02;
                    float fE = androidx.compose.ui.geometry.b.e(jC) - fC02;
                    androidx.compose.ui.geometry.c cVar2 = new androidx.compose.ui.geometry.c(fD, fE, androidx.compose.ui.geometry.b.d(jC) + fC02, androidx.compose.ui.geometry.b.e(jC) + fC02);
                    dVar.f0(j4, f4, f5 - f4, Q4.c(fD, fE), T4.a(cVar2.e(), cVar2.d()), (768 & 64) != 0 ? 1.0f : fFloatValue2, new androidx.compose.ui.graphics.drawscope.h(dVar.c0(f6), DefinitionKt.NO_Float_VALUE, 0, 0, 26));
                    androidx.compose.material3.pulltorefresh.g.c(dVar, o, cVar2, j4, fFloatValue2, f0Var);
                    androidx.compose.animation.d0.y(cVarE0, jR);
                    return Unit.a;
                } catch (Throwable th2) {
                    androidx.compose.animation.d0.y(cVarE0, jR);
                    throw th2;
                }
            default:
                androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) obj;
                int i = qVar.b;
                long j5 = this.b;
                int iE = i > androidx.compose.ui.text.K.e(j5) ? qVar.b : androidx.compose.ui.text.K.e(j5);
                int iD = androidx.compose.ui.text.K.d(j5);
                int iD2 = qVar.c;
                if (iD2 >= iD) {
                    iD2 = androidx.compose.ui.text.K.d(j5);
                }
                long jC2 = AbstractC3205m5.c(qVar.b(iE), qVar.b(iD2));
                kotlin.jvm.internal.H h = (kotlin.jvm.internal.H) this.d;
                int i2 = h.a;
                C0982b c0982b2 = qVar.a;
                int iE2 = androidx.compose.ui.text.K.e(jC2);
                int iD3 = androidx.compose.ui.text.K.d(jC2);
                androidx.compose.ui.text.android.x xVar = c0982b2.d;
                Layout layout = xVar.e;
                int length = layout.getText().length();
                if (iE2 < 0) {
                    throw new IllegalArgumentException("startOffset must be > 0");
                }
                if (iE2 >= length) {
                    throw new IllegalArgumentException("startOffset must be less than text length");
                }
                if (iD3 <= iE2) {
                    throw new IllegalArgumentException("endOffset must be greater than startOffset");
                }
                if (iD3 > length) {
                    throw new IllegalArgumentException("endOffset must be smaller or equal to text length");
                }
                int i3 = (iD3 - iE2) * 4;
                float[] fArr = (float[]) this.c;
                if (fArr.length - i2 < i3) {
                    throw new IllegalArgumentException("array.size - arrayStart must be greater or equal than (endOffset - startOffset) * 4");
                }
                int lineForOffset = layout.getLineForOffset(iE2);
                int lineForOffset2 = layout.getLineForOffset(iD3 - 1);
                androidx.compose.ui.scrollcapture.j jVar = new androidx.compose.ui.scrollcapture.j(xVar);
                if (lineForOffset <= lineForOffset2) {
                    while (true) {
                        int lineStart = layout.getLineStart(lineForOffset);
                        int iF = xVar.f(lineForOffset);
                        int iMax = Math.max(iE2, lineStart);
                        int iMin = Math.min(iD3, iF);
                        float fG = xVar.g(lineForOffset);
                        float fE2 = xVar.e(lineForOffset);
                        c0982b = c0982b2;
                        j = jC2;
                        boolean z2 = false;
                        boolean z3 = layout.getParagraphDirection(lineForOffset) == 1;
                        while (iMax < iMin) {
                            boolean zIsRtlCharAt = layout.isRtlCharAt(iMax);
                            if (!z3 || zIsRtlCharAt) {
                                if (z3 && zIsRtlCharAt) {
                                    z2 = false;
                                    float fA3 = jVar.a(iMax, false, false, false);
                                    z = z3;
                                    fA = jVar.a(iMax + 1, true, true, false);
                                    fA2 = fA3;
                                } else {
                                    z = z3;
                                    z2 = false;
                                    if (z || !zIsRtlCharAt) {
                                        fA = jVar.a(iMax, false, false, false);
                                        fA2 = jVar.a(iMax + 1, true, true, false);
                                    } else {
                                        fA2 = jVar.a(iMax, false, false, true);
                                        fA = jVar.a(iMax + 1, true, true, true);
                                    }
                                }
                                fArr[i2] = fA;
                                fArr[i2 + 1] = fG;
                                fArr[i2 + 2] = fA2;
                                fArr[i2 + 3] = fE2;
                                i2 += 4;
                                iMax++;
                                z3 = z;
                            } else {
                                fA = jVar.a(iMax, z2, z2, true);
                                z = z3;
                                fA2 = jVar.a(iMax + 1, true, true, true);
                            }
                            z2 = false;
                            fArr[i2] = fA;
                            fArr[i2 + 1] = fG;
                            fArr[i2 + 2] = fA2;
                            fArr[i2 + 3] = fE2;
                            i2 += 4;
                            iMax++;
                            z3 = z;
                        }
                        if (lineForOffset != lineForOffset2) {
                            lineForOffset++;
                            c0982b2 = c0982b;
                            jC2 = j;
                        }
                    }
                } else {
                    c0982b = c0982b2;
                    j = jC2;
                }
                int iC = (androidx.compose.ui.text.K.c(j) * 4) + h.a;
                int i4 = h.a;
                while (true) {
                    kotlin.jvm.internal.G g2 = (kotlin.jvm.internal.G) this.e;
                    if (i4 >= iC) {
                        h.a = iC;
                        g2.a = c0982b.b() + g2.a;
                        return Unit.a;
                    }
                    int i5 = i4 + 1;
                    float f7 = fArr[i5];
                    float f8 = g2.a;
                    fArr[i5] = f7 + f8;
                    int i6 = i4 + 3;
                    fArr[i6] = fArr[i6] + f8;
                    i4 += 4;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0552u(Object obj, Object obj2, long j, Object obj3, int i) {
        super(1);
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.b = j;
        this.e = obj3;
    }
}
