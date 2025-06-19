package com.quizlet.remote.model.entitlements;

import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteMeteringMeta {
    public final int a;
    public final int b;

    public RemoteMeteringMeta(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteMeteringMeta)) {
            return false;
        }
        RemoteMeteringMeta remoteMeteringMeta = (RemoteMeteringMeta) obj;
        return this.a == remoteMeteringMeta.a && this.b == remoteMeteringMeta.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteMeteringMeta(numEvents=");
        sb.append(this.a);
        sb.append(", threshold=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
