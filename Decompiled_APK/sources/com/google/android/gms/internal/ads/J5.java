package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class J5 {
    public final int a;
    public final int b;
    public final int c;
    public final boolean d;
    public final com.android.billingclient.api.s e;
    public final C2338m1 f;
    public int n;
    public final Object g = new Object();
    public final ArrayList h = new ArrayList();
    public final ArrayList i = new ArrayList();
    public final ArrayList j = new ArrayList();
    public int k = 0;
    public int l = 0;
    public int m = 0;
    public String o = "";
    public String p = "";
    public String q = "";

    public J5(int i, int i2, int i3, int i4, int i5, int i6, int i7, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = z;
        this.e = new com.android.billingclient.api.s(i4);
        C2338m1 c2338m1 = new C2338m1();
        c2338m1.a = i5;
        i6 = (i6 > 64 || i6 < 0) ? 64 : i6;
        if (i7 <= 0) {
            c2338m1.b = 1;
        } else {
            c2338m1.b = i7;
        }
        c2338m1.c = new S5(i6);
        this.f = c2338m1;
    }

    public static final String d(ArrayList arrayList) {
        if (arrayList.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            sb.append((String) arrayList.get(i));
            sb.append(' ');
            i++;
            if (sb.length() > 100) {
                break;
            }
        }
        sb.deleteCharAt(sb.length() - 1);
        String string = sb.toString();
        return string.length() < 100 ? string : string.substring(0, 100);
    }

    public final void a(String str, boolean z, float f, float f2, float f3, float f4) {
        c(str, z, f, f2, f3, f4);
        synchronized (this.g) {
            try {
                if (this.m < 0) {
                    com.google.android.gms.ads.internal.util.client.i.d("ActivityContent: negative number of WebViews.");
                }
                b();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        synchronized (this.g) {
            try {
                int i = this.k;
                int i2 = this.l;
                boolean z = this.d;
                int i3 = this.b;
                if (!z) {
                    i3 = (i2 * i3) + (i * this.a);
                }
                if (i3 > this.n) {
                    this.n = i3;
                    com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                    if (!jVar.h.d().i()) {
                        com.android.billingclient.api.s sVar = this.e;
                        this.o = sVar.o(this.h);
                        this.p = sVar.o(this.i);
                    }
                    if (!jVar.h.d().j()) {
                        this.q = this.f.b(this.i, this.j);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void c(String str, boolean z, float f, float f2, float f3, float f4) {
        if (str != null) {
            if (str.length() < this.c) {
                return;
            }
            synchronized (this.g) {
                try {
                    this.h.add(str);
                    this.k += str.length();
                    if (z) {
                        this.i.add(str);
                        this.j.add(new O5(f, f2, f3, f4, r10.size() - 1));
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof J5)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        String str = ((J5) obj).o;
        return str != null && str.equals(this.o);
    }

    public final int hashCode() {
        return this.o.hashCode();
    }

    public final String toString() {
        ArrayList arrayList = this.h;
        int i = this.l;
        int i2 = this.n;
        int i3 = this.k;
        String strD = d(arrayList);
        String strD2 = d(this.i);
        String str = this.o;
        String str2 = this.p;
        String str3 = this.q;
        StringBuilder sbW = android.support.v4.media.session.a.w("ActivityContent fetchId: ", i, " score:", " total_length:", i2);
        sbW.append(i3);
        sbW.append("\n text: ");
        sbW.append(strD);
        sbW.append("\n viewableText");
        androidx.compose.ui.node.B.u(sbW, strD2, "\n signture: ", str, "\n viewableSignture: ");
        return AbstractC0147y.g(sbW, str2, "\n viewableSignatureForVertical: ", str3);
    }
}
