package com.quizlet.features.paywall.state;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements c {
    public final String a;
    public final String b;

    public b(String message, String header) {
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(header, "header");
        this.a = message;
        this.b = header;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String a() {
        return this.a;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String b() {
        return "";
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String c() {
        return "";
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Loading(message=");
        sb.append(this.a);
        sb.append(", header=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
