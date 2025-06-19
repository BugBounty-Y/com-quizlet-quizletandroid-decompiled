package com.quizlet.remote.model.user;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FullUserModels {
    public final List a;

    public FullUserModels(@InterfaceC4853h(name = "user") List<RemoteFullUser> list) {
        this.a = list;
    }

    @NotNull
    public final FullUserModels copy(@InterfaceC4853h(name = "user") List<RemoteFullUser> list) {
        return new FullUserModels(list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FullUserModels) && Intrinsics.b(this.a, ((FullUserModels) obj).a);
    }

    public final int hashCode() {
        List list = this.a;
        if (list == null) {
            return 0;
        }
        return list.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("FullUserModels(user="), this.a);
    }
}
