package com.quizlet.remote.model.search;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSearchSocialSignalForSets {
    public final int a;
    public final int b;
    public final String c;
    public final boolean d;
    public final Long e;
    public final String f;
    public final long g;

    public RemoteSearchSocialSignalForSets(@InterfaceC4853h(name = "numStudiers") int i, @InterfaceC4853h(name = "time") int i2, @InterfaceC4853h(name = "timeUnit") @NotNull String timeUnit, @InterfaceC4853h(name = "largeTimeRange") boolean z, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l, @InterfaceC4853h(name = "schoolName") String str, @InterfaceC4853h(name = "studiableId") long j) {
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        this.a = i;
        this.b = i2;
        this.c = timeUnit;
        this.d = z;
        this.e = l;
        this.f = str;
        this.g = j;
    }

    @NotNull
    public final RemoteSearchSocialSignalForSets copy(@InterfaceC4853h(name = "numStudiers") int i, @InterfaceC4853h(name = "time") int i2, @InterfaceC4853h(name = "timeUnit") @NotNull String timeUnit, @InterfaceC4853h(name = "largeTimeRange") boolean z, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l, @InterfaceC4853h(name = "schoolName") String str, @InterfaceC4853h(name = "studiableId") long j) {
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        return new RemoteSearchSocialSignalForSets(i, i2, timeUnit, z, l, str, j);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSearchSocialSignalForSets)) {
            return false;
        }
        RemoteSearchSocialSignalForSets remoteSearchSocialSignalForSets = (RemoteSearchSocialSignalForSets) obj;
        return this.a == remoteSearchSocialSignalForSets.a && this.b == remoteSearchSocialSignalForSets.b && Intrinsics.b(this.c, remoteSearchSocialSignalForSets.c) && this.d == remoteSearchSocialSignalForSets.d && Intrinsics.b(this.e, remoteSearchSocialSignalForSets.e) && Intrinsics.b(this.f, remoteSearchSocialSignalForSets.f) && this.g == remoteSearchSocialSignalForSets.g;
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31, this.c), 31, this.d);
        Long l = this.e;
        int iHashCode = (iG + (l == null ? 0 : l.hashCode())) * 31;
        String str = this.f;
        return Long.hashCode(this.g) + ((iHashCode + (str != null ? str.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSearchSocialSignalForSets(numStudiers=");
        sb.append(this.a);
        sb.append(", time=");
        sb.append(this.b);
        sb.append(", timeUnit=");
        sb.append(this.c);
        sb.append(", largeTimeRange=");
        sb.append(this.d);
        sb.append(", schoolId=");
        sb.append(this.e);
        sb.append(", schoolName=");
        sb.append(this.f);
        sb.append(", studiableId=");
        return android.support.v4.media.session.a.g(this.g, ")", sb);
    }
}
