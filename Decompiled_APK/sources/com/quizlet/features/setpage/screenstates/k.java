package com.quizlet.features.setpage.screenstates;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3550w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends AbstractC3550w {
    public final String a;
    public final long b;

    public k(String title, long j) {
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = title;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && this.b == kVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LogScreenLoad(title=");
        sb.append(this.a);
        sb.append(", setId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
