package com.google.android.gms.internal.ads;

import java.util.Comparator;

/* renamed from: com.google.android.gms.internal.ads.bu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1897bu extends AbstractC1983du {
    public static final AbstractC1983du f(int i) {
        return i < 0 ? AbstractC1983du.b : i > 0 ? AbstractC1983du.c : AbstractC1983du.a;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1983du
    public final int a() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1983du
    public final AbstractC1983du b(int i, int i2) {
        return f(Integer.compare(i, i2));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1983du
    public final AbstractC1983du c(Object obj, Object obj2, Comparator comparator) {
        return f(comparator.compare(obj, obj2));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1983du
    public final AbstractC1983du d(boolean z, boolean z2) {
        return f(Boolean.compare(z, z2));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1983du
    public final AbstractC1983du e(boolean z, boolean z2) {
        return f(Boolean.compare(z2, z));
    }
}
