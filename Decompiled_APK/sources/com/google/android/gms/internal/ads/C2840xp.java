package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.xp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2840xp extends androidx.sqlite.db.b {
    public final long c;
    public final ArrayList d;
    public final ArrayList e;

    public C2840xp(int i, long j) {
        super(i, 1);
        this.c = j;
        this.d = new ArrayList();
        this.e = new ArrayList();
    }

    @Override // androidx.sqlite.db.b
    public final String toString() {
        ArrayList arrayList = this.d;
        return androidx.sqlite.db.b.t(this.b) + " leaves: " + Arrays.toString(arrayList.toArray()) + " containers: " + Arrays.toString(this.e.toArray());
    }

    public final C2840xp v(int i) {
        ArrayList arrayList = this.e;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            C2840xp c2840xp = (C2840xp) arrayList.get(i2);
            if (c2840xp.b == i) {
                return c2840xp;
            }
        }
        return null;
    }

    public final Mp w(int i) {
        ArrayList arrayList = this.d;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            Mp mp = (Mp) arrayList.get(i2);
            if (mp.b == i) {
                return mp;
            }
        }
        return null;
    }
}
