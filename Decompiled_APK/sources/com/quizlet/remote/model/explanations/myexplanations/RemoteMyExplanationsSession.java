package com.quizlet.remote.model.explanations.myexplanations;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteMyExplanationsSession {
    public final long a;
    public final int b;
    public final String c;
    public final int d;
    public final long e;
    public final boolean f;

    public RemoteMyExplanationsSession(@InterfaceC4853h(name = "personId") long j, @InterfaceC4853h(name = DBSessionFields.Names.ITEM_TYPE) int i, @InterfaceC4853h(name = DBSessionFields.Names.ITEM_ID) @NotNull String itemId, @InterfaceC4853h(name = "platform") int i2, @InterfaceC4853h(name = "timestamp") long j2, @InterfaceC4853h(name = "active") boolean z) {
        Intrinsics.checkNotNullParameter(itemId, "itemId");
        this.a = j;
        this.b = i;
        this.c = itemId;
        this.d = i2;
        this.e = j2;
        this.f = z;
    }

    @NotNull
    public final RemoteMyExplanationsSession copy(@InterfaceC4853h(name = "personId") long j, @InterfaceC4853h(name = DBSessionFields.Names.ITEM_TYPE) int i, @InterfaceC4853h(name = DBSessionFields.Names.ITEM_ID) @NotNull String itemId, @InterfaceC4853h(name = "platform") int i2, @InterfaceC4853h(name = "timestamp") long j2, @InterfaceC4853h(name = "active") boolean z) {
        Intrinsics.checkNotNullParameter(itemId, "itemId");
        return new RemoteMyExplanationsSession(j, i, itemId, i2, j2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteMyExplanationsSession)) {
            return false;
        }
        RemoteMyExplanationsSession remoteMyExplanationsSession = (RemoteMyExplanationsSession) obj;
        return this.a == remoteMyExplanationsSession.a && this.b == remoteMyExplanationsSession.b && Intrinsics.b(this.c, remoteMyExplanationsSession.c) && this.d == remoteMyExplanationsSession.d && this.e == remoteMyExplanationsSession.e && this.f == remoteMyExplanationsSession.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.d(d0.b(this.d, d0.e(d0.b(this.b, Long.hashCode(this.a) * 31, 31), 31, this.c), 31), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteMyExplanationsSession(personId=");
        sb.append(this.a);
        sb.append(", itemType=");
        sb.append(this.b);
        sb.append(", itemId=");
        sb.append(this.c);
        sb.append(", platform=");
        sb.append(this.d);
        sb.append(", timestampSec=");
        sb.append(this.e);
        sb.append(", active=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }

    public /* synthetic */ RemoteMyExplanationsSession(long j, int i, String str, int i2, long j2, boolean z, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, i, str, i2, j2, (i3 & 32) != 0 ? true : z);
    }
}
