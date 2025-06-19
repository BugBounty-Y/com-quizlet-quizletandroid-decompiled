package com.quizlet.remote.model.studiablemetadata;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteStudiableMetadata {
    public final long a;
    public final long b;
    public final int c;
    public final Long d;

    public RemoteStudiableMetadata(@InterfaceC4853h(name = "personId") long j, @InterfaceC4853h(name = DBProgressResetFields.Names.CONTAINER_ID) long j2, @InterfaceC4853h(name = DBProgressResetFields.Names.CONTAINER_TYPE) int i, @InterfaceC4853h(name = "resetTime") Long l) {
        this.a = j;
        this.b = j2;
        this.c = i;
        this.d = l;
    }

    @NotNull
    public final RemoteStudiableMetadata copy(@InterfaceC4853h(name = "personId") long j, @InterfaceC4853h(name = DBProgressResetFields.Names.CONTAINER_ID) long j2, @InterfaceC4853h(name = DBProgressResetFields.Names.CONTAINER_TYPE) int i, @InterfaceC4853h(name = "resetTime") Long l) {
        return new RemoteStudiableMetadata(j, j2, i, l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteStudiableMetadata)) {
            return false;
        }
        RemoteStudiableMetadata remoteStudiableMetadata = (RemoteStudiableMetadata) obj;
        return this.a == remoteStudiableMetadata.a && this.b == remoteStudiableMetadata.b && this.c == remoteStudiableMetadata.c && Intrinsics.b(this.d, remoteStudiableMetadata.d);
    }

    public final int hashCode() {
        int iB = d0.b(this.c, d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31);
        Long l = this.d;
        return iB + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "RemoteStudiableMetadata(personId=" + this.a + ", containerId=" + this.b + ", containerType=" + this.c + ", resetTime=" + this.d + ")";
    }
}
