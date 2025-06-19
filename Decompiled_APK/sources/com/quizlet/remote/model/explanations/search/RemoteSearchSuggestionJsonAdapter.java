package com.quizlet.remote.model.explanations.search;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteSearchSuggestionJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteSearchSuggestionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("suggestion", "rank");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "suggestion");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "rank");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("suggestion", "suggestion", reader);
                }
            } else if (iK0 == 1 && (num = (Integer) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("rank", "rank", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("suggestion", "suggestion", reader);
        }
        if (num != null) {
            return new RemoteSearchSuggestion(str, num.intValue());
        }
        throw com.squareup.moshi.internal.b.e("rank", "rank", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSearchSuggestion remoteSearchSuggestion = (RemoteSearchSuggestion) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSearchSuggestion == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("suggestion");
        this.b.g(writer, remoteSearchSuggestion.a);
        writer.l("rank");
        this.c.g(writer, Integer.valueOf(remoteSearchSuggestion.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(RemoteSearchSuggestion)", "toString(...)");
    }
}
