package com.google.common.base;

/* loaded from: classes2.dex */
public final class k extends i {
    public final Object a;

    public k(Object obj) {
        this.a = obj;
    }

    @Override // com.google.common.base.i
    public final Object a() {
        return this.a;
    }

    @Override // com.google.common.base.i
    public final boolean b() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof k) {
            return this.a.equals(((k) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() + 1502476572;
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Optional.of("), this.a, ")");
    }
}
