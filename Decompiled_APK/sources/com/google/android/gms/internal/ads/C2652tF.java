package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.tF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2652tF {
    public final int a;
    public final boolean b;

    public C2652tF(int i, boolean z) {
        this.a = i;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2652tF.class != obj.getClass()) {
            return false;
        }
        C2652tF c2652tF = (C2652tF) obj;
        return this.a == c2652tF.a && this.b == c2652tF.b;
    }

    public final int hashCode() {
        return (this.a * 31) + (this.b ? 1 : 0);
    }
}
