package com.google.common.base;

/* loaded from: classes2.dex */
public final class a extends i {
    public static final a a = new a();

    private Object readResolve() {
        return a;
    }

    @Override // com.google.common.base.i
    public final Object a() {
        throw new IllegalStateException("Optional.get() cannot be called on an absent value");
    }

    @Override // com.google.common.base.i
    public final boolean b() {
        return false;
    }

    public final boolean equals(Object obj) {
        return obj == this;
    }

    public final int hashCode() {
        return 2040732332;
    }

    public final String toString() {
        return "Optional.absent()";
    }
}
