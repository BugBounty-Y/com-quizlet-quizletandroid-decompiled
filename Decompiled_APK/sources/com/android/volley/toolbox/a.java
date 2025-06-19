package com.android.volley.toolbox;

import java.util.ArrayList;
import java.util.Collections;

/* loaded from: classes.dex */
public final class a {
    public static final androidx.constraintlayout.core.e e = new androidx.constraintlayout.core.e(22);
    public int a;
    public final ArrayList b;
    public final int c;
    public final Object d;

    public a(int i, ArrayList arrayList, int i2, e eVar) {
        this.a = i;
        this.b = arrayList;
        this.c = i2;
        this.d = eVar;
    }

    public synchronized byte[] a(int i) {
        for (int i2 = 0; i2 < ((ArrayList) this.d).size(); i2++) {
            byte[] bArr = (byte[]) ((ArrayList) this.d).get(i2);
            if (bArr.length >= i) {
                this.a -= bArr.length;
                ((ArrayList) this.d).remove(i2);
                this.b.remove(bArr);
                return bArr;
            }
        }
        return new byte[i];
    }

    public synchronized void b(byte[] bArr) {
        if (bArr != null) {
            if (bArr.length <= this.c) {
                this.b.add(bArr);
                int iBinarySearch = Collections.binarySearch((ArrayList) this.d, bArr, e);
                if (iBinarySearch < 0) {
                    iBinarySearch = (-iBinarySearch) - 1;
                }
                ((ArrayList) this.d).add(iBinarySearch, bArr);
                this.a += bArr.length;
                synchronized (this) {
                    while (this.a > this.c) {
                        byte[] bArr2 = (byte[]) this.b.remove(0);
                        ((ArrayList) this.d).remove(bArr2);
                        this.a -= bArr2.length;
                    }
                }
            }
        }
    }

    public a() {
        this.b = new ArrayList();
        this.d = new ArrayList(64);
        this.a = 0;
        this.c = 4096;
    }
}
