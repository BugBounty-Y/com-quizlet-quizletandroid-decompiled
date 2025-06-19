package com.quizlet.remote.model.explanations.toc;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteChapter implements a {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final List e;
    public final List f;

    public RemoteChapter(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") String str, @InterfaceC4853h(name = "name") String str2, @InterfaceC4853h(name = "hasSolutions") boolean z, @InterfaceC4853h(name = "children") List<? extends a> list, @InterfaceC4853h(name = "exercises") List<RemoteExercise> list2) {
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = z;
        this.e = list;
        this.f = list2;
    }

    @NotNull
    public final RemoteChapter copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") String str, @InterfaceC4853h(name = "name") String str2, @InterfaceC4853h(name = "hasSolutions") boolean z, @InterfaceC4853h(name = "children") List<? extends a> list, @InterfaceC4853h(name = "exercises") List<RemoteExercise> list2) {
        return new RemoteChapter(j, str, str2, z, list, list2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteChapter)) {
            return false;
        }
        RemoteChapter remoteChapter = (RemoteChapter) obj;
        return this.a == remoteChapter.a && Intrinsics.b(this.b, remoteChapter.b) && Intrinsics.b(this.c, remoteChapter.c) && this.d == remoteChapter.d && Intrinsics.b(this.e, remoteChapter.e) && Intrinsics.b(this.f, remoteChapter.f);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iG = d0.g((iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.d);
        List list = this.e;
        int iHashCode3 = (iG + (list == null ? 0 : list.hashCode())) * 31;
        List list2 = this.f;
        return iHashCode3 + (list2 != null ? list2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteChapter(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", name=");
        sb.append(this.c);
        sb.append(", hasSolutions=");
        sb.append(this.d);
        sb.append(", children=");
        sb.append(this.e);
        sb.append(", exercises=");
        return android.support.v4.media.session.a.n(")", sb, this.f);
    }
}
