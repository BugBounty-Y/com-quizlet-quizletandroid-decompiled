package com.quizlet.quizletandroid.ui.common.images.loading.offline;

import androidx.compose.animation.d0;
import com.quizlet.qutils.data.offline.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final com.quizlet.qutils.data.offline.c b;
    public final com.quizlet.qutils.data.offline.b c;
    public final boolean d;
    public final com.quizlet.qutils.data.offline.a e;
    public final d f;

    public a(String source) {
        com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
        com.quizlet.qutils.data.offline.b priority = com.quizlet.qutils.data.offline.b.b;
        com.quizlet.qutils.data.offline.a network = com.quizlet.qutils.data.offline.a.b;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(ttl, "ttl");
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(network, "network");
        this.a = source;
        this.b = ttl;
        this.c = priority;
        this.d = true;
        this.e = network;
        this.f = new d(source, ttl, true, priority, network);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && this.c == aVar.c && this.d == aVar.d && this.e == aVar.e;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.g((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31, 31, this.d);
    }

    public final String toString() {
        return "ImagePayload(source=" + this.a + ", ttl=" + this.b + ", priority=" + this.c + ", isCancelable=" + this.d + ", network=" + this.e + ")";
    }
}
