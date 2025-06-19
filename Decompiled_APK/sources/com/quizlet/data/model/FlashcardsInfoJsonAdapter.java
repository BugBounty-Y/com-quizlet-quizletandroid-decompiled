package com.quizlet.data.model;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsInfoJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public volatile Constructor f;

    public FlashcardsInfoJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "status", "setId", "cards");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(EnumC4175w.class, m, "status");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Long.class, m, "setId");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(com.squareup.moshi.H.f(List.class, FlashcardsTermDefinitionCard.class), m, "cards");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        EnumC4175w enumC4175w = null;
        Long l = null;
        List list = null;
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
                l = (Long) this.d.a(reader);
                i &= -5;
            } else if (iK0 == 3) {
                list = (List) this.e.a(reader);
                i &= -9;
            }
        }
        reader.i();
        if (i == -13) {
            if (str == null) {
                throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
            }
            if (enumC4175w != null) {
                return new FlashcardsInfo(str, enumC4175w, l, list);
            }
            throw com.squareup.moshi.internal.b.e("status", "status", reader);
        }
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = FlashcardsInfo.class.getDeclaredConstructor(String.class, EnumC4175w.class, Long.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
        }
        if (enumC4175w == null) {
            throw com.squareup.moshi.internal.b.e("status", "status", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(str, enumC4175w, l, list, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (FlashcardsInfo) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        FlashcardsInfo flashcardsInfo = (FlashcardsInfo) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (flashcardsInfo == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        this.b.g(writer, flashcardsInfo.a);
        writer.l("status");
        this.c.g(writer, flashcardsInfo.b);
        writer.l("setId");
        this.d.g(writer, flashcardsInfo.c);
        writer.l("cards");
        this.e.g(writer, flashcardsInfo.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(FlashcardsInfo)", "toString(...)");
    }
}
