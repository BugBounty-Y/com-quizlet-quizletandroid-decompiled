package com.quizlet.data.model;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class NotesToValueInfoJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public final com.squareup.moshi.l h;
    public final com.squareup.moshi.l i;
    public final com.squareup.moshi.l j;
    public volatile Constructor k;

    public NotesToValueInfoJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "isVisible", "title", "outlineMarkdown", "reviewSheet", "flashcards", "essay", "user", "originalUpload", "userModifiedAt", "createdAt");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Boolean.TYPE, m, "isVisible");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(TitleInfo.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(OutlineMarkdownInfo.class, m, "outlineMarkdown");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(ReviewSheetInfo.class, m, "reviewSheet");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(FlashcardsInfo.class, m, "flashcards");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        com.squareup.moshi.l lVarA7 = moshi.a(EssayInfo.class, m, "essay");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        com.squareup.moshi.l lVarA8 = moshi.a(User.class, m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
        com.squareup.moshi.l lVarA9 = moshi.a(String.class, m, "userModifiedAt");
        Intrinsics.checkNotNullExpressionValue(lVarA9, "adapter(...)");
        this.j = lVarA9;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i2 = -1;
        String str = null;
        Boolean bool = null;
        TitleInfo titleInfo = null;
        OutlineMarkdownInfo outlineMarkdownInfo = null;
        ReviewSheetInfo reviewSheetInfo = null;
        FlashcardsInfo flashcardsInfo = null;
        EssayInfo essayInfo = null;
        User user = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        while (true) {
            String str5 = str;
            Boolean bool2 = bool;
            if (!reader.l()) {
                TitleInfo titleInfo2 = titleInfo;
                reader.i();
                if (i2 == -1661) {
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
                    }
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.e("isVisible", "isVisible", reader);
                    }
                    boolean zBooleanValue = bool2.booleanValue();
                    if (user == null) {
                        throw com.squareup.moshi.internal.b.e("user", "user", reader);
                    }
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.e("originalUpload", "originalUpload", reader);
                    }
                    String str6 = str2;
                    User user2 = user;
                    EssayInfo essayInfo2 = essayInfo;
                    return new NotesToValueInfo(str5, zBooleanValue, titleInfo2, outlineMarkdownInfo, reviewSheetInfo, flashcardsInfo, essayInfo2, user2, str6, str3, str4);
                }
                Constructor declaredConstructor = this.k;
                if (declaredConstructor == null) {
                    i = i2;
                    declaredConstructor = NotesToValueInfo.class.getDeclaredConstructor(String.class, Boolean.TYPE, TitleInfo.class, OutlineMarkdownInfo.class, ReviewSheetInfo.class, FlashcardsInfo.class, EssayInfo.class, User.class, String.class, String.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
                    this.k = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    i = i2;
                }
                Constructor constructor = declaredConstructor;
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
                }
                if (bool2 == null) {
                    throw com.squareup.moshi.internal.b.e("isVisible", "isVisible", reader);
                }
                if (user == null) {
                    throw com.squareup.moshi.internal.b.e("user", "user", reader);
                }
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.e("originalUpload", "originalUpload", reader);
                }
                Object objNewInstance = constructor.newInstance(str5, bool2, titleInfo2, outlineMarkdownInfo, reviewSheetInfo, flashcardsInfo, essayInfo, user, str2, str3, str4, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (NotesToValueInfo) objNewInstance;
            }
            TitleInfo titleInfo3 = titleInfo;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 0:
                    str = (String) this.b.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("uuid", "uuid", reader);
                    }
                    titleInfo = titleInfo3;
                    bool = bool2;
                case 1:
                    bool = (Boolean) this.c.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("isVisible", "isVisible", reader);
                    }
                    titleInfo = titleInfo3;
                    str = str5;
                case 2:
                    titleInfo = (TitleInfo) this.d.a(reader);
                    i2 &= -5;
                    str = str5;
                    bool = bool2;
                case 3:
                    outlineMarkdownInfo = (OutlineMarkdownInfo) this.e.a(reader);
                    i2 &= -9;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 4:
                    reviewSheetInfo = (ReviewSheetInfo) this.f.a(reader);
                    i2 &= -17;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 5:
                    flashcardsInfo = (FlashcardsInfo) this.g.a(reader);
                    i2 &= -33;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 6:
                    essayInfo = (EssayInfo) this.h.a(reader);
                    i2 &= -65;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 7:
                    user = (User) this.i.a(reader);
                    if (user == null) {
                        throw com.squareup.moshi.internal.b.k("user", "user", reader);
                    }
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 8:
                    str2 = (String) this.b.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("originalUpload", "originalUpload", reader);
                    }
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 9:
                    str3 = (String) this.j.a(reader);
                    i2 &= -513;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                case 10:
                    str4 = (String) this.j.a(reader);
                    i2 &= -1025;
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
                default:
                    titleInfo = titleInfo3;
                    str = str5;
                    bool = bool2;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        NotesToValueInfo notesToValueInfo = (NotesToValueInfo) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (notesToValueInfo == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, notesToValueInfo.a);
        writer.l("isVisible");
        this.c.g(writer, Boolean.valueOf(notesToValueInfo.b));
        writer.l("title");
        this.d.g(writer, notesToValueInfo.c);
        writer.l("outlineMarkdown");
        this.e.g(writer, notesToValueInfo.d);
        writer.l("reviewSheet");
        this.f.g(writer, notesToValueInfo.e);
        writer.l("flashcards");
        this.g.g(writer, notesToValueInfo.f);
        writer.l("essay");
        this.h.g(writer, notesToValueInfo.g);
        writer.l("user");
        this.i.g(writer, notesToValueInfo.h);
        writer.l("originalUpload");
        lVar.g(writer, notesToValueInfo.i);
        writer.l("userModifiedAt");
        com.squareup.moshi.l lVar2 = this.j;
        lVar2.g(writer, notesToValueInfo.j);
        writer.l("createdAt");
        lVar2.g(writer, notesToValueInfo.k);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(38, "GeneratedJsonAdapter(NotesToValueInfo)", "toString(...)");
    }
}
