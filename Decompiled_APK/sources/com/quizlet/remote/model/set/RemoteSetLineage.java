package com.quizlet.remote.model.set;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSetLineage {
    public final int a;
    public final String b;

    public RemoteSetLineage(@InterfaceC4853h(name = "level") int i, @InterfaceC4853h(name = "name") @NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    @NotNull
    public final RemoteSetLineage copy(@InterfaceC4853h(name = "level") int i, @InterfaceC4853h(name = "name") @NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return new RemoteSetLineage(i, name);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSetLineage)) {
            return false;
        }
        RemoteSetLineage remoteSetLineage = (RemoteSetLineage) obj;
        return this.a == remoteSetLineage.a && Intrinsics.b(this.b, remoteSetLineage.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "RemoteSetLineage(level=" + this.a + ", name=" + this.b + ")";
    }
}
