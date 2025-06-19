package com.quizlet.data.model;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ReviewSheetInfoJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public volatile Constructor e;

    public ReviewSheetInfoJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "status", "reviewSheet");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(EnumC4175w.class, m, "status");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "reviewSheet");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        EnumC4175w enumC4175w = null;
        String str2 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("uuid", "uuid", reader);
                }
            } else if (iK0 == 1) {
                enumC4175w = (EnumC4175w) this.c.a(reader);
                if (enumC4175w == null) {
                    throw com.squareup.moshi.internal.b.k("status", "status", reader);
                }
            } else if (iK0 == 2) {
                str2 = (String) this.d.a(reader);
                i = -5;
            }
        }
        reader.i();
        if (i == -5) {
            if (str == null) {
                throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
            }
            if (enumC4175w != null) {
                return new ReviewSheetInfo(str, enumC4175w, str2);
            }
            throw com.squareup.moshi.internal.b.e("status", "status", reader);
        }
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            declaredConstructor = ReviewSheetInfo.class.getDeclaredConstructor(String.class, EnumC4175w.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
        }
        if (enumC4175w == null) {
            throw com.squareup.moshi.internal.b.e("status", "status", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(str, enumC4175w, str2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (ReviewSheetInfo) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        ReviewSheetInfo reviewSheetInfo = (ReviewSheetInfo) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (reviewSheetInfo == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        this.b.g(writer, reviewSheetInfo.a);
        writer.l("status");
        this.c.g(writer, reviewSheetInfo.b);
        writer.l("reviewSheet");
        this.d.g(writer, reviewSheetInfo.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(ReviewSheetInfo)", "toString(...)");
    }
}
