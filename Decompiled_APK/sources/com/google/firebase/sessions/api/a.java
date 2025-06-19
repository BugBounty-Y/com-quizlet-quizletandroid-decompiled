package com.google.firebase.sessions.api;

import com.google.firebase.crashlytics.internal.common.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final kotlinx.coroutines.sync.c a;
    public h b;

    public a(kotlinx.coroutines.sync.c mutex) {
        Intrinsics.checkNotNullParameter(mutex, "mutex");
        this.a = mutex;
        this.b = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        h hVar = this.b;
        return iHashCode + (hVar == null ? 0 : hVar.hashCode());
    }

    public final String toString() {
        return "Dependency(mutex=" + this.a + ", subscriber=" + this.b + ')';
    }
}
