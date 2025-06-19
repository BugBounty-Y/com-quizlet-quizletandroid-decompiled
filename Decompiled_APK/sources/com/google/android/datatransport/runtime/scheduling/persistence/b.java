package com.google.android.datatransport.runtime.scheduling.persistence;

/* loaded from: classes2.dex */
public final class b {
    public final long a;
    public final com.google.android.datatransport.runtime.i b;
    public final com.google.android.datatransport.runtime.h c;

    public b(long j, com.google.android.datatransport.runtime.i iVar, com.google.android.datatransport.runtime.h hVar) {
        this.a = j;
        this.b = iVar;
        this.c = hVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof b) {
            b bVar = (b) obj;
            if (this.a == bVar.a && this.b.equals(bVar.b) && this.c.equals(bVar.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        long j = this.a;
        return ((((((int) ((j >>> 32) ^ j)) ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        return "PersistedEvent{id=" + this.a + ", transportContext=" + this.b + ", event=" + this.c + "}";
    }
}
