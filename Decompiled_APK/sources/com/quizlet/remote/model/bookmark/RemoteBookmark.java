package com.quizlet.remote.model.bookmark;

import android.support.v4.media.session.a;
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
public final class RemoteBookmark {
    public final Long a;
    public final long b;
    public final long c;
    public final Long d;
    public final boolean e;

    public RemoteBookmark(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "personId") long j, long j2, Long l2, boolean z) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = l2;
        this.e = z;
    }

    @NotNull
    public final RemoteBookmark copy(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "personId") long j, long j2, Long l2, boolean z) {
        return new RemoteBookmark(l, j, j2, l2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteBookmark)) {
            return false;
        }
        RemoteBookmark remoteBookmark = (RemoteBookmark) obj;
        return Intrinsics.b(this.a, remoteBookmark.a) && this.b == remoteBookmark.b && this.c == remoteBookmark.c && Intrinsics.b(this.d, remoteBookmark.d) && this.e == remoteBookmark.e;
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = d0.d(d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c);
        Long l2 = this.d;
        return Boolean.hashCode(this.e) + ((iD + (l2 != null ? l2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteBookmark(localId=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", isDeleted=");
        return a.o(")", sb, this.e);
    }

    public /* synthetic */ RemoteBookmark(Long l, long j, long j2, Long l2, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(l, j, j2, l2, (i & 16) != 0 ? false : z);
    }
}
