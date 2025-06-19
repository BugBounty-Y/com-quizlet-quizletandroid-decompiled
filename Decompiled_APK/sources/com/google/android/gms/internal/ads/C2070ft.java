package com.google.android.gms.internal.ads;

import java.util.function.Predicate;

/* renamed from: com.google.android.gms.internal.ads.ft, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2070ft implements Predicate {
    @Override // java.util.function.Predicate
    public final boolean test(Object obj) {
        String str = (String) obj;
        if (str == null) {
            str = "";
        }
        return !str.trim().isEmpty();
    }
}
