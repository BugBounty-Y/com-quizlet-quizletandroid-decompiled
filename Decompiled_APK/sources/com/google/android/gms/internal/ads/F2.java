package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class F2 implements Comparable {
    public final int a;
    public final C2897z2 b;

    public F2(int i, C2897z2 c2897z2) {
        this.a = i;
        this.b = c2897z2;
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Object obj) {
        return Integer.compare(this.a, ((F2) obj).a);
    }
}
