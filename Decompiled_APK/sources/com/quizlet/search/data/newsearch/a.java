package com.quizlet.search.data.newsearch;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d, c, b, e {
    public final com.quizlet.search.ads.b a;

    public a(com.quizlet.search.ads.b bVar) {
        this.a = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        com.quizlet.search.ads.b bVar = this.a;
        if (bVar == null) {
            return 0;
        }
        return bVar.hashCode();
    }

    public final String toString() {
        return "SearchAd(adViewData=" + this.a + ")";
    }
}
