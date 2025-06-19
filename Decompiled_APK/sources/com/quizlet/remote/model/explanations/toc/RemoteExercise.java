package com.quizlet.remote.model.explanations.toc;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteExercise {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final String e;

    public RemoteExercise(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "mediaExerciseId") String str, @InterfaceC4853h(name = "exerciseName") @NotNull String name, @InterfaceC4853h(name = "hasSolution") boolean z, @InterfaceC4853h(name = "_webUrl") @NotNull String webUrl) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        this.a = j;
        this.b = str;
        this.c = name;
        this.d = z;
        this.e = webUrl;
    }

    @NotNull
    public final RemoteExercise copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "mediaExerciseId") String str, @InterfaceC4853h(name = "exerciseName") @NotNull String name, @InterfaceC4853h(name = "hasSolution") boolean z, @InterfaceC4853h(name = "_webUrl") @NotNull String webUrl) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        return new RemoteExercise(j, str, name, z, webUrl);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteExercise)) {
            return false;
        }
        RemoteExercise remoteExercise = (RemoteExercise) obj;
        return this.a == remoteExercise.a && Intrinsics.b(this.b, remoteExercise.b) && Intrinsics.b(this.c, remoteExercise.c) && this.d == remoteExercise.d && Intrinsics.b(this.e, remoteExercise.e);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return this.e.hashCode() + d0.g(d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteExercise(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", name=");
        sb.append(this.c);
        sb.append(", hasSolution=");
        sb.append(this.d);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
