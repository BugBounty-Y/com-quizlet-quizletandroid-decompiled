package com.quizlet.data.model;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumnImageJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public volatile Constructor c;

    public SolutionColumnImageJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("large", "regular");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        com.squareup.moshi.l lVarA = moshi.a(SimpleImage.class, kotlin.collections.M.a, "large");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SimpleImage simpleImage = null;
        SimpleImage simpleImage2 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                simpleImage = (SimpleImage) this.b.a(reader);
                i = -2;
            } else if (iK0 == 1) {
                simpleImage2 = (SimpleImage) this.b.a(reader);
            }
        }
        reader.i();
        if (i == -2) {
            return new SolutionColumnImage(simpleImage, simpleImage2);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = SolutionColumnImage.class.getDeclaredConstructor(SimpleImage.class, SimpleImage.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(simpleImage, simpleImage2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (SolutionColumnImage) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        SolutionColumnImage solutionColumnImage = (SolutionColumnImage) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (solutionColumnImage == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("large");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, solutionColumnImage.a);
        writer.l("regular");
        lVar.g(writer, solutionColumnImage.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(SolutionColumnImage)", "toString(...)");
    }
}
