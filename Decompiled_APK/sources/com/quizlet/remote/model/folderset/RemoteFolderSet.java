package com.quizlet.remote.model.folderset;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolderSet {
    public final Long a;
    public final long b;
    public final long c;
    public final Long d;
    public final Boolean e;
    public final Long f;
    public final Long g;
    public final boolean h;

    public RemoteFolderSet(@InterfaceC4853h(name = "clientId") Long l, long j, long j2, Long l2, Boolean bool, Long l3, Long l4, boolean z) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = l2;
        this.e = bool;
        this.f = l3;
        this.g = l4;
        this.h = z;
    }

    @NotNull
    public final RemoteFolderSet copy(@InterfaceC4853h(name = "clientId") Long l, long j, long j2, Long l2, Boolean bool, Long l3, Long l4, boolean z) {
        return new RemoteFolderSet(l, j, j2, l2, bool, l3, l4, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFolderSet)) {
            return false;
        }
        RemoteFolderSet remoteFolderSet = (RemoteFolderSet) obj;
        return Intrinsics.b(this.a, remoteFolderSet.a) && this.b == remoteFolderSet.b && this.c == remoteFolderSet.c && Intrinsics.b(this.d, remoteFolderSet.d) && Intrinsics.b(this.e, remoteFolderSet.e) && Intrinsics.b(this.f, remoteFolderSet.f) && Intrinsics.b(this.g, remoteFolderSet.g) && this.h == remoteFolderSet.h;
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = d0.d(d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c);
        Long l2 = this.d;
        int iHashCode = (iD + (l2 == null ? 0 : l2.hashCode())) * 31;
        Boolean bool = this.e;
        int iHashCode2 = (iHashCode + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l3 = this.f;
        int iHashCode3 = (iHashCode2 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.g;
        return Boolean.hashCode(this.h) + ((iHashCode3 + (l4 != null ? l4.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFolderSet(localId=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", isDeleted=");
        sb.append(this.e);
        sb.append(", clientTimestamp=");
        sb.append(this.f);
        sb.append(", lastModified=");
        sb.append(this.g);
        sb.append(", isDirty=");
        return android.support.v4.media.session.a.o(")", sb, this.h);
    }

    public /* synthetic */ RemoteFolderSet(Long l, long j, long j2, Long l2, Boolean bool, Long l3, Long l4, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(l, j, j2, l2, bool, l3, l4, (i & 128) != 0 ? false : z);
    }
}
