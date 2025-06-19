package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;

/* renamed from: com.google.android.gms.internal.ads.mF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2352mF implements InterfaceC2005eF, InterfaceC1962dF {
    public final InterfaceC2005eF[] a;
    public final boolean[] b;
    public final IdentityHashMap c;
    public final ArrayList d = new ArrayList();
    public final HashMap e = new HashMap();
    public InterfaceC1962dF f;
    public HF g;
    public InterfaceC2005eF[] h;
    public VE i;

    public C2352mF(long[] jArr, InterfaceC2005eF... interfaceC2005eFArr) {
        this.a = interfaceC2005eFArr;
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        this.i = new VE(bu, bu);
        this.c = new IdentityHashMap();
        this.h = new InterfaceC2005eF[0];
        this.b = new boolean[interfaceC2005eFArr.length];
        for (int i = 0; i < interfaceC2005eFArr.length; i++) {
            long j = jArr[i];
            if (j != 0) {
                this.b[i] = true;
                this.a[i] = new GF(interfaceC2005eFArr[i], j);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        return this.i.a();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        return this.i.b();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long c(long j) {
        long jC = this.h[0].c(j);
        int i = 1;
        while (true) {
            InterfaceC2005eF[] interfaceC2005eFArr = this.h;
            if (i >= interfaceC2005eFArr.length) {
                return jC;
            }
            if (interfaceC2005eFArr[i].c(jC) != jC) {
                throw new IllegalStateException("Unexpected child seekToUs result.");
            }
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        this.i.d(j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void e(InterfaceC1962dF interfaceC1962dF, long j) {
        this.f = interfaceC1962dF;
        ArrayList arrayList = this.d;
        InterfaceC2005eF[] interfaceC2005eFArr = this.a;
        Collections.addAll(arrayList, interfaceC2005eFArr);
        for (InterfaceC2005eF interfaceC2005eF : interfaceC2005eFArr) {
            interfaceC2005eF.e(this, j);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long f(long j, OD od) {
        InterfaceC2005eF[] interfaceC2005eFArr = this.h;
        return (interfaceC2005eFArr.length > 0 ? interfaceC2005eFArr[0] : this.a[0]).f(j, od);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final /* bridge */ /* synthetic */ void g(BF bf) {
        InterfaceC1962dF interfaceC1962dF = this.f;
        interfaceC1962dF.getClass();
        interfaceC1962dF.g(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final HF h() {
        HF hf = this.g;
        hf.getClass();
        return hf;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void i() {
        int i = 0;
        while (true) {
            InterfaceC2005eF[] interfaceC2005eFArr = this.a;
            if (i >= interfaceC2005eFArr.length) {
                return;
            }
            interfaceC2005eFArr[i].i();
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long j() {
        long j = -9223372036854775807L;
        for (InterfaceC2005eF interfaceC2005eF : this.h) {
            long j2 = interfaceC2005eF.j();
            if (j2 == -9223372036854775807L) {
                if (j != -9223372036854775807L && interfaceC2005eF.c(j) != j) {
                    throw new IllegalStateException("Unexpected child seekToUs result.");
                }
            } else if (j == -9223372036854775807L) {
                for (InterfaceC2005eF interfaceC2005eF2 : this.h) {
                    if (interfaceC2005eF2 == interfaceC2005eF) {
                        break;
                    }
                    if (interfaceC2005eF2.c(j2) != j2) {
                        throw new IllegalStateException("Unexpected child seekToUs result.");
                    }
                }
                j = j2;
            } else if (j2 != j) {
                throw new IllegalStateException("Conflicting discontinuities.");
            }
        }
        return j;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        ArrayList arrayList = this.d;
        if (arrayList.isEmpty()) {
            return this.i.k(c2607sD);
        }
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((InterfaceC2005eF) arrayList.get(i)).k(c2607sD);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final void l(InterfaceC2005eF interfaceC2005eF) {
        InterfaceC2005eF[] interfaceC2005eFArr;
        ArrayList arrayList = this.d;
        arrayList.remove(interfaceC2005eF);
        if (arrayList.isEmpty()) {
            int i = 0;
            int i2 = 0;
            while (true) {
                interfaceC2005eFArr = this.a;
                if (i >= interfaceC2005eFArr.length) {
                    break;
                }
                i2 += interfaceC2005eFArr[i].h().a;
                i++;
            }
            J9[] j9Arr = new J9[i2];
            int i3 = 0;
            for (int i4 = 0; i4 < interfaceC2005eFArr.length; i4++) {
                HF hfH = interfaceC2005eFArr[i4].h();
                int i5 = hfH.a;
                int i6 = 0;
                while (i6 < i5) {
                    J9 j9A = hfH.a(i6);
                    int i7 = j9A.a;
                    C1832aG[] c1832aGArr = new C1832aG[i7];
                    for (int i8 = 0; i8 < i7; i8++) {
                        C1832aG c1832aG = j9A.d[i8];
                        c1832aG.getClass();
                        EF ef = new EF(c1832aG);
                        String str = c1832aG.a;
                        if (str == null) {
                            str = "";
                        }
                        ef.a = i4 + ":" + str;
                        c1832aGArr[i8] = new C1832aG(ef);
                    }
                    J9 j9 = new J9(i4 + ":" + j9A.b, c1832aGArr);
                    this.e.put(j9, j9A);
                    j9Arr[i3] = j9;
                    i6++;
                    i3++;
                }
            }
            this.g = new HF(j9Arr);
            InterfaceC1962dF interfaceC1962dF = this.f;
            interfaceC1962dF.getClass();
            interfaceC1962dF.l(this);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long m(XF[] xfArr, boolean[] zArr, AF[] afArr, boolean[] zArr2, long j) {
        int length;
        IdentityHashMap identityHashMap;
        int[] iArr;
        int[] iArr2;
        int length2 = xfArr.length;
        int[] iArr3 = new int[length2];
        int[] iArr4 = new int[length2];
        int i = 0;
        int i2 = 0;
        while (true) {
            length = xfArr.length;
            identityHashMap = this.c;
            if (i2 >= length) {
                break;
            }
            AF af = afArr[i2];
            Integer num = af == null ? null : (Integer) identityHashMap.get(af);
            iArr3[i2] = num == null ? -1 : num.intValue();
            XF xf = xfArr[i2];
            if (xf != null) {
                String str = xf.a().b;
                iArr4[i2] = Integer.parseInt(str.substring(0, str.indexOf(":")));
            } else {
                iArr4[i2] = -1;
            }
            i2++;
        }
        identityHashMap.clear();
        AF[] afArr2 = new AF[length];
        AF[] afArr3 = new AF[length];
        XF[] xfArr2 = new XF[length];
        InterfaceC2005eF[] interfaceC2005eFArr = this.a;
        ArrayList arrayList = new ArrayList(interfaceC2005eFArr.length);
        long j2 = j;
        int i3 = 0;
        while (i3 < interfaceC2005eFArr.length) {
            int i4 = i;
            while (i4 < xfArr.length) {
                afArr3[i4] = iArr3[i4] == i3 ? afArr[i4] : null;
                if (iArr4[i4] == i3) {
                    XF xf2 = xfArr[i4];
                    xf2.getClass();
                    iArr = iArr4;
                    iArr2 = iArr3;
                    J9 j9 = (J9) this.e.get(xf2.a());
                    j9.getClass();
                    xfArr2[i4] = new C2309lF(xf2, j9);
                } else {
                    iArr = iArr4;
                    iArr2 = iArr3;
                    xfArr2[i4] = null;
                }
                i4++;
                iArr4 = iArr;
                iArr3 = iArr2;
            }
            int[] iArr5 = iArr4;
            int[] iArr6 = iArr3;
            ArrayList arrayList2 = arrayList;
            InterfaceC2005eF[] interfaceC2005eFArr2 = interfaceC2005eFArr;
            int i5 = i3;
            long jM = interfaceC2005eFArr[i3].m(xfArr2, zArr, afArr3, zArr2, j2);
            if (i5 == 0) {
                j2 = jM;
            } else if (jM != j2) {
                throw new IllegalStateException("Children enabled at different positions.");
            }
            boolean z = false;
            for (int i6 = 0; i6 < xfArr.length; i6++) {
                if (iArr5[i6] == i5) {
                    AF af2 = afArr3[i6];
                    af2.getClass();
                    afArr2[i6] = af2;
                    identityHashMap.put(af2, Integer.valueOf(i5));
                    z = true;
                } else if (iArr6[i6] == i5) {
                    AbstractC1795We.L(afArr3[i6] == null);
                }
            }
            if (z) {
                arrayList2.add(interfaceC2005eFArr2[i5]);
            }
            i3 = i5 + 1;
            arrayList = arrayList2;
            interfaceC2005eFArr = interfaceC2005eFArr2;
            iArr4 = iArr5;
            iArr3 = iArr6;
            i = 0;
        }
        int i7 = i;
        ArrayList arrayList3 = arrayList;
        System.arraycopy(afArr2, i7, afArr, i7, length);
        this.h = (InterfaceC2005eF[]) arrayList3.toArray(new InterfaceC2005eF[i7]);
        this.i = new VE(arrayList3, AbstractC1981ds.n(arrayList3, new C2853y1(21)));
        return j2;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        return this.i.o();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void r(long j) {
        for (InterfaceC2005eF interfaceC2005eF : this.h) {
            interfaceC2005eF.r(j);
        }
    }
}
