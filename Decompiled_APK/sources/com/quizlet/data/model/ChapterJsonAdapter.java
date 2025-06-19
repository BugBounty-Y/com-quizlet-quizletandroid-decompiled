package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ChapterJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;

    public ChapterJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "hasSolutions", "title", "name", "children", "exercises");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Boolean.TYPE, m, "hasSolutions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(com.squareup.moshi.H.f(List.class, TableOfContentItem.class), m, "children");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(com.squareup.moshi.H.f(List.class, Exercise.class), m, "exercises");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        List list = null;
        List list2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            com.squareup.moshi.l lVar = this.d;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    break;
                case 1:
                    bool = (Boolean) this.c.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("hasSolutions", "hasSolutions", reader);
                    }
                    break;
                case 2:
                    str = (String) lVar.a(reader);
                    break;
                case 3:
                    str2 = (String) lVar.a(reader);
                    break;
                case 4:
                    list = (List) this.e.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("children", "children", reader);
                    }
                    break;
                case 5:
                    list2 = (List) this.f.a(reader);
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.k("exercises", "exercises", reader);
                    }
                    break;
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (bool == null) {
            throw com.squareup.moshi.internal.b.e("hasSolutions", "hasSolutions", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("children", "children", reader);
        }
        if (list2 != null) {
            return new Chapter(jLongValue, str, str2, zBooleanValue, list, list2);
        }
        throw com.squareup.moshi.internal.b.e("exercises", "exercises", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Chapter chapter = (Chapter) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (chapter == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(chapter.a));
        writer.l("hasSolutions");
        this.c.g(writer, Boolean.valueOf(chapter.b));
        writer.l("title");
        com.squareup.moshi.l lVar = this.d;
        lVar.g(writer, chapter.c);
        writer.l("name");
        lVar.g(writer, chapter.d);
        writer.l("children");
        this.e.g(writer, chapter.e);
        writer.l("exercises");
        this.f.g(writer, chapter.f);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(29, "GeneratedJsonAdapter(Chapter)", "toString(...)");
    }
}
