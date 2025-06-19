package com.quizlet.shared.models.api.studyset;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class TermsResponse implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new C5048d(TermMetadata$$serializer.INSTANCE, 0)};
    public final List a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TermsResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TermsResponse(int i, List list) {
        if (1 == (i & 1)) {
            this.a = list;
        } else {
            AbstractC5047c0.k(i, 1, TermsResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof TermsResponse) && Intrinsics.b(this.a, ((TermsResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("TermsResponse(terms="), this.a);
    }

    public TermsResponse(List terms) {
        Intrinsics.checkNotNullParameter(terms, "terms");
        this.a = terms;
    }
}
