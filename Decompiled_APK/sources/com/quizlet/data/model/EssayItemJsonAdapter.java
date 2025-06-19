package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class EssayItemJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;

    public EssayItemJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("prompt", "difficulty");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "prompt");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(T.class, m, "difficulty");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        T t = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("prompt", "prompt", reader);
                }
            } else if (iK0 == 1 && (t = (T) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("difficulty", "difficulty", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("prompt", "prompt", reader);
        }
        if (t != null) {
            return new EssayItem(str, t);
        }
        throw com.squareup.moshi.internal.b.e("difficulty", "difficulty", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        EssayItem essayItem = (EssayItem) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (essayItem == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("prompt");
        this.b.g(writer, essayItem.a);
        writer.l("difficulty");
        this.c.g(writer, essayItem.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(31, "GeneratedJsonAdapter(EssayItem)", "toString(...)");
    }
}
