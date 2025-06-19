package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSetClassification {
    public final long a;
    public final double b;
    public final List c;

    public RemoteSetClassification(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = DBSessionFields.Names.SCORE) double d, @InterfaceC4853h(name = "lineage") @NotNull List<RemoteSetLineage> lineage) {
        Intrinsics.checkNotNullParameter(lineage, "lineage");
        this.a = j;
        this.b = d;
        this.c = lineage;
    }

    @NotNull
    public final RemoteSetClassification copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = DBSessionFields.Names.SCORE) double d, @InterfaceC4853h(name = "lineage") @NotNull List<RemoteSetLineage> lineage) {
        Intrinsics.checkNotNullParameter(lineage, "lineage");
        return new RemoteSetClassification(j, d, lineage);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSetClassification)) {
            return false;
        }
        RemoteSetClassification remoteSetClassification = (RemoteSetClassification) obj;
        return this.a == remoteSetClassification.a && Double.compare(this.b, remoteSetClassification.b) == 0 && Intrinsics.b(this.c, remoteSetClassification.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.a(this.b, Long.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSetClassification(id=");
        sb.append(this.a);
        sb.append(", score=");
        sb.append(this.b);
        sb.append(", lineage=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }
}
