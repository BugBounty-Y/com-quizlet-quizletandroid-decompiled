package com.ionspin.kotlin.bignum.integer;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final c a;
    public final c b;

    public a(c quotient, c remainder) {
        Intrinsics.checkNotNullParameter(quotient, "quotient");
        Intrinsics.checkNotNullParameter(remainder, "remainder");
        this.a = quotient;
        this.b = remainder;
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
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "QuotientAndRemainder(quotient=" + this.a + ", remainder=" + this.b + ')';
    }
}
