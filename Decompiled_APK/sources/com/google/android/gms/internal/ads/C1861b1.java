package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.b1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1861b1 extends W0 {
    public final String b;
    public final AbstractC2330lu c;

    public C1861b1(String str, String str2, Bu bu) {
        super(str);
        AbstractC1795We.B(!bu.isEmpty());
        this.b = str2;
        AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(bu);
        this.c = abstractC2330luN;
    }

    public static ArrayList b(String str) {
        ArrayList arrayList = new ArrayList();
        try {
            if (str.length() >= 10) {
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(0, 4))));
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(5, 7))));
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(8, 10))));
                return arrayList;
            }
            if (str.length() >= 7) {
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(0, 4))));
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(5, 7))));
                return arrayList;
            }
            if (str.length() >= 4) {
                arrayList.add(Integer.valueOf(Integer.parseInt(str.substring(0, 4))));
            }
            return arrayList;
        } catch (NumberFormatException unused) {
            return new ArrayList();
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0114  */
    @Override // com.google.android.gms.internal.ads.W0, com.google.android.gms.internal.ads.InterfaceC2856y4
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(com.google.android.gms.internal.ads.L3 r9) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 714
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1861b1.a(com.google.android.gms.internal.ads.L3):void");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1861b1.class == obj.getClass()) {
            C1861b1 c1861b1 = (C1861b1) obj;
            if (Objects.equals(this.a, c1861b1.a) && Objects.equals(this.b, c1861b1.b) && this.c.equals(c1861b1.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() + 527;
        String str = this.b;
        return this.c.hashCode() + (((iHashCode * 31) + (str != null ? str.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.gms.internal.ads.W0
    public final String toString() {
        String strValueOf = String.valueOf(this.c);
        StringBuilder sb = new StringBuilder();
        sb.append(this.a);
        sb.append(": description=");
        return AbstractC0147y.g(sb, this.b, ": values=", strValueOf);
    }
}
