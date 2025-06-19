package com.google.android.gms.internal.ads;

import android.content.SharedPreferences;
import android.util.SparseArray;
import androidx.compose.foundation.lazy.layout.C0429a;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;

/* loaded from: classes2.dex */
public class I3 implements M, Pk {
    public static final B2 e = new B2(2);
    public final /* synthetic */ int a;
    public int b;
    public Object c;
    public Object d;

    public /* synthetic */ I3(int i, C1868b8 c1868b8, C1868b8 c1868b82) {
        this.a = 8;
        this.b = i;
        this.c = c1868b8;
        this.d = c1868b82;
    }

    public static I3 h(long j, String str) {
        return new I3(str, 2, Long.valueOf(j));
    }

    private final /* synthetic */ void k() {
    }

    public static I3 n(String str, boolean z) {
        return new I3(str, 1, Boolean.valueOf(z));
    }

    public int a() {
        int i = this.b;
        if (i == 2) {
            return 2048;
        }
        if (i != 3) {
            return 0;
        }
        return com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        WD wd = (WD) obj;
        int i = C2221jD.i1;
        int i2 = this.b;
        if (i2 == 1) {
            wd.i = false;
            i2 = 1;
        }
        PD pd = wd.g;
        pd.getClass();
        C2084g6 c2084g6 = wd.d;
        c2084g6.d = C2084g6.t(pd, (AbstractC2330lu) c2084g6.b, (C2093gF) c2084g6.e, (C2303l9) c2084g6.a);
        RD rdG = wd.g();
        wd.i(rdG, 11, new com.airbnb.lottie.parser.l(rdG, i2, (C1868b8) this.c, (C1868b8) this.d));
    }

    public Object c(int i) {
        SparseArray sparseArray;
        if (this.b == -1) {
            this.b = 0;
        }
        while (true) {
            int i2 = this.b;
            sparseArray = (SparseArray) this.c;
            if (i2 <= 0 || i >= sparseArray.keyAt(i2)) {
                break;
            }
            this.b--;
        }
        while (this.b < sparseArray.size() - 1 && i >= sparseArray.keyAt(this.b + 1)) {
            this.b++;
        }
        return sparseArray.valueAt(this.b);
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00ac, code lost:
    
        if (r13 == r16) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00ae, code lost:
    
        r12 = new com.google.android.gms.internal.ads.L(r13, r6 + r8, -2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00ba, code lost:
    
        return com.google.android.gms.internal.ads.L.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:?, code lost:
    
        return r12;
     */
    @Override // com.google.android.gms.internal.ads.M
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.L d(com.google.android.gms.internal.ads.P r25, long r26) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.I3.d(com.google.android.gms.internal.ads.P, long):com.google.android.gms.internal.ads.L");
    }

    public void e(J5 j5) {
        synchronized (this.c) {
            try {
                LinkedList linkedList = (LinkedList) this.d;
                if (linkedList.size() >= 10) {
                    com.google.android.gms.ads.internal.util.client.i.d("Queue is full, current size = " + linkedList.size());
                    linkedList.remove(0);
                }
                int i = this.b;
                this.b = i + 1;
                j5.l = i;
                synchronized (j5.g) {
                    try {
                        int i2 = j5.k;
                        int i3 = j5.l;
                        boolean z = j5.d;
                        int i4 = j5.b;
                        if (!z) {
                            i4 = (i3 * i4) + (i2 * j5.a);
                        }
                        if (i4 > j5.n) {
                            j5.n = i4;
                        }
                    } finally {
                    }
                }
                linkedList.add(j5);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void f(Object obj, Object obj2) {
        int i = this.b + 1;
        Object[] objArr = (Object[]) this.c;
        int length = objArr.length;
        int i2 = i + i;
        if (i2 > length) {
            this.c = Arrays.copyOf(objArr, AbstractC2027eu.h(length, i2));
        }
        AbstractC2543qs.p(obj, obj2);
        Object[] objArr2 = (Object[]) this.c;
        int i3 = this.b;
        int i4 = i3 + i3;
        objArr2[i4] = obj;
        objArr2[i4 + 1] = obj2;
        this.b = i3 + 1;
    }

    public synchronized void g(byte[] bArr) {
        if (bArr != null) {
            int length = bArr.length;
            if (length <= 4096) {
                ((ArrayList) this.c).add(bArr);
                ArrayList arrayList = (ArrayList) this.d;
                int iBinarySearch = Collections.binarySearch(arrayList, bArr, e);
                if (iBinarySearch < 0) {
                    iBinarySearch = (-iBinarySearch) - 1;
                }
                arrayList.add(iBinarySearch, bArr);
                this.b += length;
                synchronized (this) {
                    while (this.b > 4096) {
                        byte[] bArr2 = (byte[]) ((ArrayList) this.c).remove(0);
                        ((ArrayList) this.d).remove(bArr2);
                        this.b -= bArr2.length;
                    }
                }
            }
        }
    }

    public void i(J5 j5) {
        synchronized (this.c) {
            try {
                Iterator it2 = ((LinkedList) this.d).iterator();
                while (it2.hasNext()) {
                    J5 j52 = (J5) it2.next();
                    com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                    if (jVar.h.d().i()) {
                        if (!jVar.h.d().j() && !j5.equals(j52) && j52.q.equals(j5.q)) {
                            it2.remove();
                            return;
                        }
                    } else if (!j5.equals(j52) && j52.o.equals(j5.o)) {
                        it2.remove();
                        return;
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public synchronized byte[] j(int i) {
        int i2 = 0;
        while (true) {
            ArrayList arrayList = (ArrayList) this.d;
            if (i2 >= arrayList.size()) {
                return new byte[i];
            }
            byte[] bArr = (byte[]) arrayList.get(i2);
            int length = bArr.length;
            if (length >= i) {
                this.b -= length;
                arrayList.remove(i2);
                ((ArrayList) this.c).remove(bArr);
                return bArr;
            }
            i2++;
        }
    }

    public long l(P p) throws EOFException, InterruptedIOException {
        long j;
        C0429a c0429a;
        Z z;
        long j2;
        int iB;
        while (true) {
            long jZze = p.zze();
            j = p.c;
            long j3 = j - 6;
            c0429a = (C0429a) this.d;
            z = (Z) this.c;
            if (jZze >= j3) {
                j2 = -6;
                break;
            }
            long jZze2 = p.zze();
            byte[] bArr = new byte[2];
            p.k(bArr, 0, 2, false);
            int i = ((bArr[0] & 255) << 8) | (bArr[1] & 255);
            int i2 = this.b;
            if (i == i2) {
                j2 = -6;
                Kn kn = new Kn(16);
                System.arraycopy(bArr, 0, kn.a, 0, 2);
                byte[] bArr2 = kn.a;
                int i3 = 0;
                for (int i4 = 2; i3 < 14 && (iB = p.b(i4 + i3, bArr2, 14 - i3)) != -1; i4 = 2) {
                    i3 += iB;
                }
                kn.i(i3);
                p.f = 0;
                p.n((int) (jZze2 - p.d), false);
                if (AbstractC1795We.v(kn, z, i2, c0429a)) {
                    break;
                }
            } else {
                p.f = 0;
                p.n((int) (jZze2 - p.d), false);
            }
            p.n(1, false);
        }
        if (p.zze() < j + j2) {
            return c0429a.a;
        }
        p.n((int) (j - p.zze()), false);
        return z.j;
    }

    public Gu m() {
        C2373mu c2373mu = (C2373mu) this.d;
        if (c2373mu != null) {
            throw c2373mu.a();
        }
        Gu guD = Gu.d(this.b, (Object[]) this.c, this);
        C2373mu c2373mu2 = (C2373mu) this.d;
        if (c2373mu2 == null) {
            return guD;
        }
        throw c2373mu2.a();
    }

    public Object o() {
        C2644t7 c2644t7 = (C2644t7) AbstractC2259k8.a.get();
        Object obj = this.d;
        if (c2644t7 == null) {
            if (AbstractC2259k8.b.get() == null) {
                return obj;
            }
            throw new ClassCastException();
        }
        int i = this.b - 1;
        String str = (String) this.c;
        SharedPreferences sharedPreferences = c2644t7.a;
        if (i == 0) {
            boolean zBooleanValue = ((Boolean) obj).booleanValue();
            try {
                return Boolean.valueOf(sharedPreferences.getBoolean(str, zBooleanValue));
            } catch (ClassCastException unused) {
                return Boolean.valueOf(sharedPreferences.getString(str, String.valueOf(zBooleanValue)));
            }
        }
        if (i == 1) {
            try {
                return Long.valueOf(sharedPreferences.getLong(str, ((Long) obj).longValue()));
            } catch (ClassCastException unused2) {
                return Long.valueOf(sharedPreferences.getInt(str, (int) r1));
            }
        }
        if (i != 2) {
            return sharedPreferences.getString(str, (String) obj);
        }
        try {
            return Double.valueOf(sharedPreferences.getFloat(str, (float) r1));
        } catch (ClassCastException unused3) {
            return Double.valueOf(sharedPreferences.getString(str, String.valueOf(((Double) obj).doubleValue())));
        }
    }

    @Override // com.google.android.gms.internal.ads.M
    /* renamed from: zzb */
    public void mo14zzb() {
        switch (this.a) {
            case 1:
                break;
            default:
                byte[] bArr = Yo.b;
                int length = bArr.length;
                ((Kn) this.d).h(0, bArr);
                break;
        }
    }

    public I3(Z z, int i) {
        this.a = 1;
        this.c = z;
        this.b = i;
        this.d = new C0429a();
    }

    public /* synthetic */ I3(C2472p6 c2472p6, byte[] bArr) {
        this.a = 5;
        this.d = c2472p6;
        this.c = bArr;
    }

    public I3(String str, int i, Object obj) {
        this.a = 6;
        this.c = str;
        this.d = obj;
        this.b = i;
    }

    public I3(int i, byte b) {
        this.a = i;
        switch (i) {
            case 4:
                this.c = new Object();
                this.d = new LinkedList();
                break;
            default:
                this.c = new ArrayList();
                this.d = new ArrayList(64);
                this.b = 0;
                break;
        }
    }

    public I3(int i, Eo eo) {
        this.a = 2;
        this.b = i;
        this.c = eo;
        this.d = new Kn();
    }

    public I3(int i, String str, int i2, ArrayList arrayList, byte[] bArr) {
        this.a = 3;
        this.b = i2;
        this.c = arrayList == null ? Collections.EMPTY_LIST : Collections.unmodifiableList(arrayList);
        this.d = bArr;
    }

    public I3(int i) {
        this.a = 7;
        this.c = new Object[i + i];
        this.b = 0;
    }

    public I3(TD td) {
        this.a = 9;
        this.c = new SparseArray();
        this.d = td;
        this.b = -1;
    }
}
