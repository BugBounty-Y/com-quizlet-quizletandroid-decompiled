package io.ktor.utils.io;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: io.ktor.utils.io.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4880a implements g {
    public final Throwable b;

    public C4880a(Throwable th) {
        this.b = th;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4880a) && Intrinsics.b(this.b, ((C4880a) obj).b);
    }

    public final int hashCode() {
        Throwable th = this.b;
        if (th == null) {
            return 0;
        }
        return th.hashCode();
    }

    public final String toString() {
        return "Closed(cause=" + this.b + ')';
    }
}
