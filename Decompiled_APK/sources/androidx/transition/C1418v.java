package androidx.transition;

import android.view.animation.AnimationUtils;
import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.layout.C0386g;
import androidx.fragment.app.RunnableC1141k;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;

/* renamed from: androidx.transition.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1418v extends z {
    public long a = -1;
    public boolean b;
    public boolean c;
    public androidx.dynamicanimation.animation.c d;
    public final C0122z e;
    public RunnableC1141k f;
    public final /* synthetic */ F g;

    public C1418v(F f) {
        this.g = f;
        C0122z c0122z = new C0122z(8, (char) 0);
        long[] jArr = new long[20];
        c0122z.c = jArr;
        c0122z.d = new float[20];
        c0122z.b = 0;
        Arrays.fill(jArr, Long.MIN_VALUE);
        this.e = c0122z;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void f(y yVar) {
        this.c = true;
    }

    public final void h() {
        float fSqrt;
        char c;
        long[] jArr;
        if (this.d != null) {
            return;
        }
        long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
        float f = this.a;
        C0122z c0122z = this.e;
        char c2 = 20;
        int i = (c0122z.b + 1) % 20;
        c0122z.b = i;
        ((long[]) c0122z.c)[i] = jCurrentAnimationTimeMillis;
        ((float[]) c0122z.d)[i] = f;
        C0386g c0386g = new C0386g(4);
        float f2 = DefinitionKt.NO_Float_VALUE;
        c0386g.b = DefinitionKt.NO_Float_VALUE;
        this.d = new androidx.dynamicanimation.animation.c(c0386g);
        androidx.dynamicanimation.animation.d dVar = new androidx.dynamicanimation.animation.d();
        dVar.b = 1.0f;
        int i2 = 0;
        dVar.c = false;
        dVar.a = Math.sqrt(200.0f);
        dVar.c = false;
        androidx.dynamicanimation.animation.c cVar = this.d;
        cVar.l = dVar;
        cVar.b = this.a;
        cVar.c = true;
        if (cVar.e) {
            throw new UnsupportedOperationException("Error: Update listeners must be added beforethe animation.");
        }
        ArrayList arrayList = cVar.k;
        if (!arrayList.contains(this)) {
            arrayList.add(this);
        }
        androidx.dynamicanimation.animation.c cVar2 = this.d;
        int i3 = c0122z.b;
        long[] jArr2 = (long[]) c0122z.c;
        long j = Long.MIN_VALUE;
        if (i3 != 0 || jArr2[i3] != Long.MIN_VALUE) {
            long j2 = jArr2[i3];
            long j3 = j2;
            while (true) {
                long j4 = jArr2[i3];
                if (j4 == j) {
                    break;
                }
                float f3 = j2 - j4;
                float fAbs = Math.abs(j4 - j3);
                if (f3 > 100.0f || fAbs > 40.0f) {
                    break;
                }
                if (i3 == 0) {
                    i3 = 20;
                }
                i3--;
                i2++;
                if (i2 >= 20) {
                    break;
                }
                j3 = j4;
                j = Long.MIN_VALUE;
            }
            if (i2 >= 2) {
                float[] fArr = (float[]) c0122z.d;
                if (i2 == 2) {
                    int i4 = c0122z.b;
                    int i5 = i4 == 0 ? 19 : i4 - 1;
                    float f4 = jArr2[i4] - jArr2[i5];
                    if (f4 != DefinitionKt.NO_Float_VALUE) {
                        fSqrt = (fArr[i4] - fArr[i5]) / f4;
                    }
                } else {
                    int i6 = c0122z.b;
                    int i7 = ((i6 - i2) + 21) % 20;
                    int i8 = (i6 + 21) % 20;
                    long j5 = jArr2[i7];
                    float f5 = fArr[i7];
                    int i9 = i7 + 1;
                    int i10 = i9 % 20;
                    float f6 = 0.0f;
                    while (i10 != i8) {
                        long j6 = jArr2[i10];
                        float f7 = f2;
                        int i11 = i8;
                        float f8 = j6 - j5;
                        if (f8 == f7) {
                            c = c2;
                            jArr = jArr2;
                        } else {
                            float f9 = fArr[i10];
                            c = c2;
                            jArr = jArr2;
                            float f10 = (f9 - f5) / f8;
                            float fAbs2 = (Math.abs(f10) * (f10 - ((float) (Math.sqrt(2.0f * Math.abs(f6)) * Math.signum(f6))))) + f6;
                            if (i10 == i9) {
                                fAbs2 *= 0.5f;
                            }
                            f6 = fAbs2;
                            f5 = f9;
                            j5 = j6;
                        }
                        i10 = (i10 + 1) % 20;
                        f2 = f7;
                        i8 = i11;
                        c2 = c;
                        jArr2 = jArr;
                    }
                    fSqrt = (float) (Math.sqrt(Math.abs(f6) * 2.0f) * Math.signum(f6));
                }
                f2 = fSqrt * 1000.0f;
            }
        }
        cVar2.a = f2;
        androidx.dynamicanimation.animation.c cVar3 = this.d;
        cVar3.f = this.g.y + 1;
        cVar3.g = -1.0f;
        cVar3.i = 4.0f;
        C1417u c1417u = new C1417u(this);
        ArrayList arrayList2 = cVar3.j;
        if (arrayList2.contains(c1417u)) {
            return;
        }
        arrayList2.add(c1417u);
    }
}
