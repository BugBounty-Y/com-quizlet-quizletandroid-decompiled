package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TableOfContentsJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;

    public TableOfContentsJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("items");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        com.squareup.moshi.l lVarA = moshi.a(com.squareup.moshi.H.f(List.class, TableOfContentItem.class), kotlin.collections.M.a, "items");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List items = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (items = (List) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("items", "items", reader);
            }
        }
        reader.i();
        if (items == null) {
            throw com.squareup.moshi.internal.b.e("items", "items", reader);
        }
        kotlin.collections.K k = TableOfContents.b;
        Intrinsics.checkNotNullParameter(items, "items");
        return new TableOfContents(items);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        TableOfContents tableOfContents = (TableOfContents) obj;
        List list = tableOfContents != null ? tableOfContents.a : null;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (list == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("items");
        this.b.g(writer, list);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(TableOfContents)", "toString(...)");
    }
}
