package com.quizlet.features.setpage.shareset;

import com.quizlet.data.model.U1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final U1 b;

    public a(String str, U1 u1) {
        this.a = str;
        this.b = u1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        U1 u1 = this.b;
        return iHashCode + (u1 != null ? u1.hashCode() : 0);
    }

    public final String toString() {
        return "SetPageAdsState(contentUrl=" + this.a + ", studySetClassification=" + this.b + ")";
    }
}
