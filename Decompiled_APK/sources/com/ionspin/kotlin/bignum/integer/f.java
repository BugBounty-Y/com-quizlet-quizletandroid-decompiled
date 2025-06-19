package com.ionspin.kotlin.bignum.integer;

import java.util.Arrays;
import kotlin.E;

/* loaded from: classes2.dex */
public final class f {
    public final Integer a;
    public final Integer b;
    public final E c;
    public final E d;
    public final Integer e;
    public final Integer f;

    public f(Integer num, Integer num2, E e, E e2, Integer num3, Integer num4) {
        this.a = num;
        this.b = num2;
        this.c = e;
        this.d = e2;
        this.e = num3;
        this.f = num4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a.equals(fVar.a) && this.b.equals(fVar.b) && this.c.equals(fVar.c) && this.d.equals(fVar.d) && this.e.equals(fVar.e) && this.f.equals(fVar.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + ((Arrays.hashCode(this.d.a) + ((Arrays.hashCode(this.c.a) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Sextuple(a=" + this.a + ", b=" + this.b + ", c=" + this.c + ", d=" + this.d + ", e=" + this.e + ", f=" + this.f + ')';
    }
}
