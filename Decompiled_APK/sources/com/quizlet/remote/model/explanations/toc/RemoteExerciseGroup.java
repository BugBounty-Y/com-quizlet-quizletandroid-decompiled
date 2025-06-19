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
public final class RemoteExerciseGroup implements a {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final List e;

    public RemoteExerciseGroup(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String title, @InterfaceC4853h(name = "page") String str, @InterfaceC4853h(name = "hasSolutions") boolean z, @InterfaceC4853h(name = "exercises") List<RemoteExercise> list) {
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = j;
        this.b = title;
        this.c = str;
        this.d = z;
        this.e = list;
    }

    @NotNull
    public final RemoteExerciseGroup copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String title, @InterfaceC4853h(name = "page") String str, @InterfaceC4853h(name = "hasSolutions") boolean z, @InterfaceC4853h(name = "exercises") List<RemoteExercise> list) {
        Intrinsics.checkNotNullParameter(title, "title");
        return new RemoteExerciseGroup(j, title, str, z, list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteExerciseGroup)) {
            return false;
        }
        RemoteExerciseGroup remoteExerciseGroup = (RemoteExerciseGroup) obj;
        return this.a == remoteExerciseGroup.a && Intrinsics.b(this.b, remoteExerciseGroup.b) && Intrinsics.b(this.c, remoteExerciseGroup.c) && this.d == remoteExerciseGroup.d && Intrinsics.b(this.e, remoteExerciseGroup.e);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iG = d0.g((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.d);
        List list = this.e;
        return iG + (list != null ? list.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteExerciseGroup(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", page=");
        sb.append(this.c);
        sb.append(", hasSolutions=");
        sb.append(this.d);
        sb.append(", exercises=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }
}
