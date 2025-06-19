package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.d0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4277d0 implements InterfaceC4289j0 {
    public final long a;
    public final String b;

    public C4277d0(long j, String label) {
        Intrinsics.checkNotNullParameter(label, "label");
        this.a = j;
        this.b = label;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4277d0)) {
            return false;
        }
        C4277d0 c4277d0 = (C4277d0) obj;
        return this.a == c4277d0.a && Intrinsics.b(this.b, c4277d0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToEditTag(id=");
        sb.append(this.a);
        sb.append(", label=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
