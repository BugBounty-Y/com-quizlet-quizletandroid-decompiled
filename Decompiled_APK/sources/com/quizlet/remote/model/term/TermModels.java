package com.quizlet.remote.model.term;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class TermModels {
    public final List a;

    public TermModels(@InterfaceC4853h(name = "term") @NotNull List<RemoteTerm> term) {
        Intrinsics.checkNotNullParameter(term, "term");
        this.a = term;
    }

    @NotNull
    public final TermModels copy(@InterfaceC4853h(name = "term") @NotNull List<RemoteTerm> term) {
        Intrinsics.checkNotNullParameter(term, "term");
        return new TermModels(term);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof TermModels) && Intrinsics.b(this.a, ((TermModels) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("TermModels(term="), this.a);
    }
}
