package androidx.compose.ui.graphics.colorspace;

import androidx.camera.camera2.internal.s0;
import androidx.compose.ui.graphics.F;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q extends c {
    public static final s0 r = new s0(7);
    public final s d;
    public final float e;
    public final float f;
    public final r g;
    public final float[] h;
    public final float[] i;
    public final float[] j;
    public final i k;
    public final p l;
    public final m m;
    public final i n;
    public final p o;
    public final m p;
    public final boolean q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:42:0x021a  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0290  */
    /* JADX WARN: Type inference failed for: r28v0 */
    /* JADX WARN: Type inference failed for: r28v1 */
    /* JADX WARN: Type inference failed for: r28v2 */
    /* JADX WARN: Type inference failed for: r29v0 */
    /* JADX WARN: Type inference failed for: r29v1 */
    /* JADX WARN: Type inference failed for: r29v2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public q(java.lang.String r34, float[] r35, androidx.compose.ui.graphics.colorspace.s r36, float[] r37, androidx.compose.ui.graphics.colorspace.i r38, androidx.compose.ui.graphics.colorspace.i r39, float r40, float r41, androidx.compose.ui.graphics.colorspace.r r42, int r43) {
        /*
            Method dump skipped, instructions count: 718
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.colorspace.q.<init>(java.lang.String, float[], androidx.compose.ui.graphics.colorspace.s, float[], androidx.compose.ui.graphics.colorspace.i, androidx.compose.ui.graphics.colorspace.i, float, float, androidx.compose.ui.graphics.colorspace.r, int):void");
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float a(int i) {
        return this.f;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float b(int i) {
        return this.e;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final boolean c() {
        return this.q;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long d(float f, float f2, float f3) {
        double d = f;
        m mVar = this.p;
        float fD = (float) mVar.d(d);
        float fD2 = (float) mVar.d(f2);
        float fD3 = (float) mVar.d(f3);
        float[] fArr = this.i;
        float f4 = (fArr[6] * fD3) + (fArr[3] * fD2) + (fArr[0] * fD);
        float f5 = (fArr[7] * fD3) + (fArr[4] * fD2) + (fArr[1] * fD);
        return (Float.floatToRawIntBits(f5) & 4294967295L) | (Float.floatToRawIntBits(f4) << 32);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final float e(float f, float f2, float f3) {
        double d = f;
        m mVar = this.p;
        float fD = (float) mVar.d(d);
        float fD2 = (float) mVar.d(f2);
        float fD3 = (float) mVar.d(f3);
        float[] fArr = this.i;
        return (fArr[8] * fD3) + (fArr[5] * fD2) + (fArr[2] * fD);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || q.class != obj.getClass() || !super.equals(obj)) {
            return false;
        }
        q qVar = (q) obj;
        if (Float.compare(qVar.e, this.e) != 0 || Float.compare(qVar.f, this.f) != 0 || !Intrinsics.b(this.d, qVar.d) || !Arrays.equals(this.h, qVar.h)) {
            return false;
        }
        r rVar = qVar.g;
        r rVar2 = this.g;
        if (rVar2 != null) {
            return Intrinsics.b(rVar2, rVar);
        }
        if (rVar == null) {
            return true;
        }
        if (Intrinsics.b(this.k, qVar.k)) {
            return Intrinsics.b(this.n, qVar.n);
        }
        return false;
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final long f(float f, float f2, float f3, float f4, c cVar) {
        float[] fArr = this.j;
        float f5 = (fArr[6] * f3) + (fArr[3] * f2) + (fArr[0] * f);
        float f6 = (fArr[7] * f3) + (fArr[4] * f2) + (fArr[1] * f);
        float f7 = (fArr[8] * f3) + (fArr[5] * f2) + (fArr[2] * f);
        m mVar = this.m;
        return F.b((float) mVar.d(f5), (float) mVar.d(f6), (float) mVar.d(f7), f4, cVar);
    }

    @Override // androidx.compose.ui.graphics.colorspace.c
    public final int hashCode() {
        int iHashCode = (Arrays.hashCode(this.h) + ((this.d.hashCode() + (super.hashCode() * 31)) * 31)) * 31;
        float f = this.e;
        int iFloatToIntBits = (iHashCode + (f == DefinitionKt.NO_Float_VALUE ? 0 : Float.floatToIntBits(f))) * 31;
        float f2 = this.f;
        int iFloatToIntBits2 = (iFloatToIntBits + (f2 == DefinitionKt.NO_Float_VALUE ? 0 : Float.floatToIntBits(f2))) * 31;
        r rVar = this.g;
        int iHashCode2 = iFloatToIntBits2 + (rVar != null ? rVar.hashCode() : 0);
        if (rVar == null) {
            return this.n.hashCode() + ((this.k.hashCode() + (iHashCode2 * 31)) * 31);
        }
        return iHashCode2;
    }

    public q(String str, float[] fArr, s sVar, final r rVar, int i) {
        i iVar;
        i iVar2;
        double d = rVar.f;
        double d2 = rVar.g;
        if (d == 0.0d && d2 == 0.0d) {
            final int i2 = 0;
            iVar = new i() { // from class: androidx.compose.ui.graphics.colorspace.o
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d3) {
                    switch (i2) {
                        case 0:
                            r rVar2 = rVar;
                            double d4 = rVar2.e;
                            double d5 = rVar2.d;
                            return d3 >= d4 * d5 ? (Math.pow(d3, 1.0d / rVar2.a) - rVar2.c) / rVar2.b : d3 / d5;
                        case 1:
                            r rVar3 = rVar;
                            double d6 = rVar3.b;
                            double d7 = rVar3.e;
                            double d8 = rVar3.d;
                            return d3 >= d7 * d8 ? (Math.pow(d3 - rVar3.f, 1.0d / rVar3.a) - rVar3.c) / d6 : (d3 - rVar3.g) / d8;
                        case 2:
                            r rVar4 = rVar;
                            return d3 >= rVar4.e ? Math.pow((rVar4.b * d3) + rVar4.c, rVar4.a) : d3 * rVar4.d;
                        default:
                            r rVar5 = rVar;
                            double d9 = rVar5.b;
                            if (d3 >= rVar5.e) {
                                return Math.pow((d9 * d3) + rVar5.c, rVar5.a) + rVar5.f;
                            }
                            return rVar5.g + (rVar5.d * d3);
                    }
                }
            };
        } else {
            final int i3 = 1;
            iVar = new i() { // from class: androidx.compose.ui.graphics.colorspace.o
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d3) {
                    switch (i3) {
                        case 0:
                            r rVar2 = rVar;
                            double d4 = rVar2.e;
                            double d5 = rVar2.d;
                            return d3 >= d4 * d5 ? (Math.pow(d3, 1.0d / rVar2.a) - rVar2.c) / rVar2.b : d3 / d5;
                        case 1:
                            r rVar3 = rVar;
                            double d6 = rVar3.b;
                            double d7 = rVar3.e;
                            double d8 = rVar3.d;
                            return d3 >= d7 * d8 ? (Math.pow(d3 - rVar3.f, 1.0d / rVar3.a) - rVar3.c) / d6 : (d3 - rVar3.g) / d8;
                        case 2:
                            r rVar4 = rVar;
                            return d3 >= rVar4.e ? Math.pow((rVar4.b * d3) + rVar4.c, rVar4.a) : d3 * rVar4.d;
                        default:
                            r rVar5 = rVar;
                            double d9 = rVar5.b;
                            if (d3 >= rVar5.e) {
                                return Math.pow((d9 * d3) + rVar5.c, rVar5.a) + rVar5.f;
                            }
                            return rVar5.g + (rVar5.d * d3);
                    }
                }
            };
        }
        if (d == 0.0d && d2 == 0.0d) {
            final int i4 = 2;
            iVar2 = new i() { // from class: androidx.compose.ui.graphics.colorspace.o
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d3) {
                    switch (i4) {
                        case 0:
                            r rVar2 = rVar;
                            double d4 = rVar2.e;
                            double d5 = rVar2.d;
                            return d3 >= d4 * d5 ? (Math.pow(d3, 1.0d / rVar2.a) - rVar2.c) / rVar2.b : d3 / d5;
                        case 1:
                            r rVar3 = rVar;
                            double d6 = rVar3.b;
                            double d7 = rVar3.e;
                            double d8 = rVar3.d;
                            return d3 >= d7 * d8 ? (Math.pow(d3 - rVar3.f, 1.0d / rVar3.a) - rVar3.c) / d6 : (d3 - rVar3.g) / d8;
                        case 2:
                            r rVar4 = rVar;
                            return d3 >= rVar4.e ? Math.pow((rVar4.b * d3) + rVar4.c, rVar4.a) : d3 * rVar4.d;
                        default:
                            r rVar5 = rVar;
                            double d9 = rVar5.b;
                            if (d3 >= rVar5.e) {
                                return Math.pow((d9 * d3) + rVar5.c, rVar5.a) + rVar5.f;
                            }
                            return rVar5.g + (rVar5.d * d3);
                    }
                }
            };
        } else {
            final int i5 = 3;
            iVar2 = new i() { // from class: androidx.compose.ui.graphics.colorspace.o
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d3) {
                    switch (i5) {
                        case 0:
                            r rVar2 = rVar;
                            double d4 = rVar2.e;
                            double d5 = rVar2.d;
                            return d3 >= d4 * d5 ? (Math.pow(d3, 1.0d / rVar2.a) - rVar2.c) / rVar2.b : d3 / d5;
                        case 1:
                            r rVar3 = rVar;
                            double d6 = rVar3.b;
                            double d7 = rVar3.e;
                            double d8 = rVar3.d;
                            return d3 >= d7 * d8 ? (Math.pow(d3 - rVar3.f, 1.0d / rVar3.a) - rVar3.c) / d6 : (d3 - rVar3.g) / d8;
                        case 2:
                            r rVar4 = rVar;
                            return d3 >= rVar4.e ? Math.pow((rVar4.b * d3) + rVar4.c, rVar4.a) : d3 * rVar4.d;
                        default:
                            r rVar5 = rVar;
                            double d9 = rVar5.b;
                            if (d3 >= rVar5.e) {
                                return Math.pow((d9 * d3) + rVar5.c, rVar5.a) + rVar5.f;
                            }
                            return rVar5.g + (rVar5.d * d3);
                    }
                }
            };
        }
        this(str, fArr, sVar, null, iVar, iVar2, DefinitionKt.NO_Float_VALUE, 1.0f, rVar, i);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public q(String str, float[] fArr, s sVar, final double d, float f, float f2, int i) {
        i iVar;
        i iVar2 = r;
        if (d == 1.0d) {
            iVar = iVar2;
        } else {
            final int i2 = 0;
            iVar = new i() { // from class: androidx.compose.ui.graphics.colorspace.n
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d2) {
                    switch (i2) {
                        case 0:
                            if (d2 < 0.0d) {
                                d2 = 0.0d;
                            }
                            return Math.pow(d2, 1.0d / d);
                        default:
                            if (d2 < 0.0d) {
                                d2 = 0.0d;
                            }
                            return Math.pow(d2, d);
                    }
                }
            };
        }
        if (d != 1.0d) {
            final int i3 = 1;
            iVar2 = new i() { // from class: androidx.compose.ui.graphics.colorspace.n
                @Override // androidx.compose.ui.graphics.colorspace.i
                public final double d(double d2) {
                    switch (i3) {
                        case 0:
                            if (d2 < 0.0d) {
                                d2 = 0.0d;
                            }
                            return Math.pow(d2, 1.0d / d);
                        default:
                            if (d2 < 0.0d) {
                                d2 = 0.0d;
                            }
                            return Math.pow(d2, d);
                    }
                }
            };
        }
        i iVar3 = iVar2;
        this(str, fArr, sVar, null, iVar, iVar3, f, f2, new r(d, 1.0d, 0.0d, 0.0d, 0.0d), i);
    }
}
