package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.IntentFilter;
import android.os.Build;
import android.util.SparseArray;
import java.util.Arrays;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.eE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2004eE {
    public static final C2004eE c = new C2004eE(AbstractC2330lu.s(C1961dE.d));
    public static final Bu d;
    public static final Gu e;
    public final SparseArray a = new SparseArray();
    public final int b;

    static {
        Object[] objArr = {2, 5, 6};
        AbstractC2457os.q(3, objArr);
        d = AbstractC2330lu.m(3, objArr);
        I3 i3 = new I3(4);
        i3.f(5, 6);
        i3.f(17, 6);
        i3.f(7, 6);
        i3.f(30, 10);
        i3.f(18, 6);
        i3.f(6, 8);
        i3.f(8, 8);
        i3.f(14, 8);
        e = i3.m();
    }

    public C2004eE(Bu bu) {
        for (int i = 0; i < bu.d; i++) {
            C1961dE c1961dE = (C1961dE) bu.get(i);
            this.a.put(c1961dE.a, c1961dE);
        }
        int iMax = 0;
        for (int i2 = 0; i2 < this.a.size(); i2++) {
            iMax = Math.max(iMax, ((C1961dE) this.a.valueAt(i2)).b);
        }
        this.b = iMax;
    }

    public static C2004eE b(Context context, Wl wl, C2883yp c2883yp) {
        return c(context, context.registerReceiver(null, new IntentFilter("android.media.action.HDMI_AUDIO_PLUG")), wl, c2883yp);
    }

    /* JADX WARN: Removed duplicated region for block: B:97:0x0288  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.C2004eE c(android.content.Context r15, android.content.Intent r16, com.google.android.gms.internal.ads.Wl r17, com.google.android.gms.internal.ads.C2883yp r18) {
        /*
            Method dump skipped, instructions count: 730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2004eE.c(android.content.Context, android.content.Intent, com.google.android.gms.internal.ads.Wl, com.google.android.gms.internal.ads.yp):com.google.android.gms.internal.ads.eE");
    }

    public static Bu d(int[] iArr, int i) {
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i2 = 0;
        int i3 = 0;
        while (i2 < iArr.length) {
            C1961dE c1961dE = new C1961dE(iArr[i2], i);
            int length = objArrCopyOf.length;
            int i4 = i3 + 1;
            int iH = AbstractC2027eu.h(length, i4);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i3] = c1961dE;
            i2++;
            i3 = i4;
        }
        return AbstractC2330lu.m(i3, objArrCopyOf);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0035  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x003f A[PHI: r2
  0x003f: PHI (r2v3 int) = (r2v2 int), (r2v6 int) binds: [B:11:0x0033, B:14:0x003b] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.util.Pair a(com.google.android.gms.internal.ads.C1832aG r17, com.google.android.gms.internal.ads.Wl r18) {
        /*
            Method dump skipped, instructions count: 296
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2004eE.a(com.google.android.gms.internal.ads.aG, com.google.android.gms.internal.ads.Wl):android.util.Pair");
    }

    public final boolean equals(Object obj) {
        if (this != obj) {
            if (obj instanceof C2004eE) {
                C2004eE c2004eE = (C2004eE) obj;
                SparseArray sparseArray = this.a;
                SparseArray sparseArray2 = c2004eE.a;
                String str = Yo.a;
                if (Build.VERSION.SDK_INT < 31) {
                    int size = sparseArray.size();
                    if (size == sparseArray2.size()) {
                        for (int i = 0; i < size; i++) {
                            if (!Objects.equals(sparseArray.valueAt(i), sparseArray2.get(sparseArray.keyAt(i)))) {
                                break;
                            }
                        }
                        if (this.b != c2004eE.b) {
                            break;
                        }
                    }
                } else if (sparseArray.contentEquals(sparseArray2)) {
                    if (this.b != c2004eE.b) {
                    }
                }
            }
            return false;
        }
        return true;
    }

    public final int hashCode() {
        int iContentHashCode;
        String str = Yo.a;
        int i = Build.VERSION.SDK_INT;
        SparseArray sparseArray = this.a;
        if (i >= 31) {
            iContentHashCode = sparseArray.contentHashCode();
        } else {
            int iHashCode = 17;
            for (int i2 = 0; i2 < sparseArray.size(); i2++) {
                iHashCode = Objects.hashCode(sparseArray.valueAt(i2)) + ((sparseArray.keyAt(i2) + (iHashCode * 31)) * 31);
            }
            iContentHashCode = iHashCode;
        }
        return (iContentHashCode * 31) + this.b;
    }

    public final String toString() {
        return "AudioCapabilities[maxChannelCount=" + this.b + ", audioProfiles=" + this.a.toString() + "]";
    }
}
