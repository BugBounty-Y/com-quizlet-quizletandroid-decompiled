package com.airbnb.lottie.compose;

/* loaded from: classes.dex */
public final class o {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof o) {
            return this.a == ((o) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("RawRes(resId="), this.a, ")");
    }
}
