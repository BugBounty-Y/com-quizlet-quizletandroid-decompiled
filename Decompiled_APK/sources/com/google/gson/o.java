package com.google.gson;

/* loaded from: classes2.dex */
public final class o extends m {
    public final com.google.gson.internal.m a = new com.google.gson.internal.m();

    public final boolean equals(Object obj) {
        if (obj != this) {
            return (obj instanceof o) && ((o) obj).a.equals(this.a);
        }
        return true;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
