package com.quizlet.quizletandroid.ui.common.ads;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4637d {
    public final int a;
    public final String b;

    public C4637d(int i, String str) {
        this.a = i;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4637d)) {
            return false;
        }
        C4637d c4637d = (C4637d) obj;
        return this.a == c4637d.a && Intrinsics.b(this.b, c4637d.b);
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        return "Input(adUnitRes=" + this.a + ", contentWebUrl=" + this.b + ")";
    }
}
