package com.quizlet.quizletandroid.ui.common.ads;

import java.util.Comparator;

/* loaded from: classes3.dex */
public final class k implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        com.google.android.gms.ads.h hVar = (com.google.android.gms.ads.h) obj2;
        com.google.android.gms.ads.h hVar2 = (com.google.android.gms.ads.h) obj;
        return kotlin.comparisons.a.b(Integer.valueOf(hVar.a * hVar.b), Integer.valueOf(hVar2.a * hVar2.b));
    }
}
