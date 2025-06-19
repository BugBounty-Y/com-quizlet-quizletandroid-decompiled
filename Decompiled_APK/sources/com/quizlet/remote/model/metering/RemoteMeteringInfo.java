package com.quizlet.remote.model.metering;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteMeteringInfo {
    public final int a;
    public final int b;

    public RemoteMeteringInfo(@InterfaceC4853h(name = "numEvents") int i, @InterfaceC4853h(name = "threshold") int i2) {
        this.a = i;
        this.b = i2;
    }

    @NotNull
    public final RemoteMeteringInfo copy(@InterfaceC4853h(name = "numEvents") int i, @InterfaceC4853h(name = "threshold") int i2) {
        return new RemoteMeteringInfo(i, i2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteMeteringInfo)) {
            return false;
        }
        RemoteMeteringInfo remoteMeteringInfo = (RemoteMeteringInfo) obj;
        return this.a == remoteMeteringInfo.a && this.b == remoteMeteringInfo.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteMeteringInfo(numEvents=");
        sb.append(this.a);
        sb.append(", threshold=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
