package com.quizlet.remote.model.practicetests;

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
public final class UpdateQuestionBankBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public UpdateQuestionBankBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("creatorId", "private");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "creatorId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "private");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Boolean bool = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("creatorId", "creatorId", reader);
                }
            } else if (iK0 == 1 && (bool = (Boolean) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("private_", "private", reader);
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("creatorId", "creatorId", reader);
        }
        long jLongValue = l.longValue();
        if (bool != null) {
            return new UpdateQuestionBankBody(jLongValue, bool.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("private_", "private", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UpdateQuestionBankBody updateQuestionBankBody = (UpdateQuestionBankBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (updateQuestionBankBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("creatorId");
        this.b.g(writer, Long.valueOf(updateQuestionBankBody.a));
        writer.l("private");
        this.c.g(writer, Boolean.valueOf(updateQuestionBankBody.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(UpdateQuestionBankBody)", "toString(...)");
    }
}
