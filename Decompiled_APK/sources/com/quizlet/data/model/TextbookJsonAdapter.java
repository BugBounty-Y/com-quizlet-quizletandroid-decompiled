package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TextbookJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;

    public TextbookJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "isbn", "title", "imageUrl", "edition", "isPremium", "verifiedSolutionCount", "authors", "imageThumbnailUrl", "hasSolutions", "webUrl", "tableOfContents");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "isbn");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Boolean.TYPE, m, "isPremium");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Integer.TYPE, m, "verifiedSolutionCount");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(TableOfContents.class, m, "tableOfContents");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Boolean bool = null;
        Integer num = null;
        Boolean bool2 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        List list = null;
        while (true) {
            Long l2 = l;
            Boolean bool3 = bool;
            Integer num2 = num;
            Boolean bool4 = bool2;
            String str8 = str;
            String str9 = str2;
            String str10 = str3;
            String str11 = str4;
            if (!reader.l()) {
                String str12 = str5;
                String str13 = str6;
                reader.i();
                if (l2 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                long jLongValue = l2.longValue();
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("isbn", "isbn", reader);
                }
                if (str9 == null) {
                    throw com.squareup.moshi.internal.b.e("title", "title", reader);
                }
                if (str10 == null) {
                    throw com.squareup.moshi.internal.b.e("imageUrl", "imageUrl", reader);
                }
                if (str11 == null) {
                    throw com.squareup.moshi.internal.b.e("edition", "edition", reader);
                }
                if (bool3 == null) {
                    throw com.squareup.moshi.internal.b.e("isPremium", "isPremium", reader);
                }
                boolean zBooleanValue = bool3.booleanValue();
                if (num2 == null) {
                    throw com.squareup.moshi.internal.b.e("verifiedSolutionCount", "verifiedSolutionCount", reader);
                }
                int iIntValue = num2.intValue();
                if (str12 == null) {
                    throw com.squareup.moshi.internal.b.e("authors", "authors", reader);
                }
                if (str13 == null) {
                    throw com.squareup.moshi.internal.b.e("imageThumbnailUrl", "imageThumbnailUrl", reader);
                }
                if (bool4 == null) {
                    throw com.squareup.moshi.internal.b.e("hasSolutions", "hasSolutions", reader);
                }
                boolean zBooleanValue2 = bool4.booleanValue();
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("webUrl", "webUrl", reader);
                }
                if (list != null) {
                    return new Textbook(jLongValue, str8, str9, str10, str11, zBooleanValue, iIntValue, str12, str13, zBooleanValue2, str7, list);
                }
                throw com.squareup.moshi.internal.b.e("tableOfContents", "tableOfContents", reader);
            }
            String str14 = str5;
            int iK0 = reader.k0(this.a);
            com.squareup.moshi.l lVar = this.d;
            String str15 = str6;
            com.squareup.moshi.l lVar2 = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 1:
                    str = (String) lVar2.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("isbn", "isbn", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 2:
                    str2 = (String) lVar2.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("title", "title", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 3:
                    str3 = (String) lVar2.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("imageUrl", "imageUrl", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 4:
                    str4 = (String) lVar2.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("edition", "edition", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str5 = str14;
                    str6 = str15;
                case 5:
                    bool = (Boolean) lVar.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("isPremium", "isPremium", reader);
                    }
                    l = l2;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 6:
                    num = (Integer) this.e.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("verifiedSolutionCount", "verifiedSolutionCount", reader);
                    }
                    l = l2;
                    bool = bool3;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 7:
                    str5 = (String) lVar2.a(reader);
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.k("authors", "authors", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str6 = str15;
                case 8:
                    str6 = (String) lVar2.a(reader);
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.k("imageThumbnailUrl", "imageThumbnailUrl", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                case 9:
                    bool2 = (Boolean) lVar.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("hasSolutions", "hasSolutions", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 10:
                    str7 = (String) lVar2.a(reader);
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.k("webUrl", "webUrl", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                case 11:
                    TableOfContents tableOfContents = (TableOfContents) this.f.a(reader);
                    list = tableOfContents != null ? tableOfContents.a : null;
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("tableOfContents", "tableOfContents", reader);
                    }
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
                default:
                    l = l2;
                    bool = bool3;
                    num = num2;
                    bool2 = bool4;
                    str = str8;
                    str2 = str9;
                    str3 = str10;
                    str4 = str11;
                    str5 = str14;
                    str6 = str15;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Textbook textbook = (Textbook) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (textbook == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(textbook.a));
        writer.l("isbn");
        com.squareup.moshi.l lVar = this.c;
        lVar.g(writer, textbook.b);
        writer.l("title");
        lVar.g(writer, textbook.c);
        writer.l("imageUrl");
        lVar.g(writer, textbook.d);
        writer.l("edition");
        lVar.g(writer, textbook.e);
        writer.l("isPremium");
        Boolean boolValueOf = Boolean.valueOf(textbook.f);
        com.squareup.moshi.l lVar2 = this.d;
        lVar2.g(writer, boolValueOf);
        writer.l("verifiedSolutionCount");
        this.e.g(writer, Integer.valueOf(textbook.g));
        writer.l("authors");
        lVar.g(writer, textbook.h);
        writer.l("imageThumbnailUrl");
        lVar.g(writer, textbook.i);
        writer.l("hasSolutions");
        com.google.android.gms.measurement.internal.Z.q(textbook.j, lVar2, writer, "webUrl");
        lVar.g(writer, textbook.k);
        writer.l("tableOfContents");
        this.f.g(writer, new TableOfContents(textbook.l));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(Textbook)", "toString(...)");
    }
}
