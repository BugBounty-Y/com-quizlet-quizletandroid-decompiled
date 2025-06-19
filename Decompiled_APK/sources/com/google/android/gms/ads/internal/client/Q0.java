package com.google.android.gms.ads.internal.client;

import java.util.Comparator;
import java.util.List;

/* loaded from: classes2.dex */
public final /* synthetic */ class Q0 implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        List list = com.google.android.gms.ads.p.e;
        return list.indexOf((String) obj) - list.indexOf((String) obj2);
    }
}
