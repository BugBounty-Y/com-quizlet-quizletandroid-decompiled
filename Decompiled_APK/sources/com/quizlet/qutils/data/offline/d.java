package com.quizlet.qutils.data.offline;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final Object a;
    public final c b;
    public final boolean c;
    public final b d;
    public final a e;

    public d(Object obj, c ttl, boolean z, b priority, a network) {
        Intrinsics.checkNotNullParameter(ttl, "ttl");
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(network, "network");
        this.a = obj;
        this.b = ttl;
        this.c = z;
        this.d = priority;
        this.e = network;
    }

    public final d a(Object obj, b priority) {
        Intrinsics.checkNotNullParameter(priority, "priority");
        return new d(obj, this.b, this.c, priority, this.e);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && this.b == dVar.b && this.c == dVar.c && this.d == dVar.d && this.e == dVar.e;
    }

    public final int hashCode() {
        Object obj = this.a;
        return this.e.hashCode() + ((this.d.hashCode() + d0.g((this.b.hashCode() + ((obj == null ? 0 : obj.hashCode()) * 31)) * 31, 31, this.c)) * 31);
    }

    public final String toString() {
        return "Payload(source=" + this.a + ", ttl=" + this.b + ", isCancelable=" + this.c + ", priority=" + this.d + ", network=" + this.e + ")";
    }
}
