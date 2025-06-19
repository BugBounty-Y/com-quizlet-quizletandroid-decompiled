package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ModelErrorJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public ModelErrorJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("message", "identifier", "code");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "serverMessage");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, "code");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        Integer num = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("serverMessage", "message", reader);
                }
            } else if (iK0 == 1) {
                str2 = (String) this.b.a(reader);
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.k("identifier", "identifier", reader);
                }
            } else if (iK0 == 2) {
                num = (Integer) this.c.a(reader);
                i = -5;
            }
        }
        reader.i();
        if (i == -5) {
            if (str == null) {
                throw com.squareup.moshi.internal.b.e("serverMessage", "message", reader);
            }
            if (str2 != null) {
                return new ModelError(str, str2, num);
            }
            throw com.squareup.moshi.internal.b.e("identifier", "identifier", reader);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = ModelError.class.getDeclaredConstructor(String.class, String.class, Integer.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("serverMessage", "message", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("identifier", "identifier", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(str, str2, num, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (ModelError) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ModelError modelError = (ModelError) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (modelError == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("message");
        l lVar = this.b;
        lVar.g(writer, modelError.a);
        writer.l("identifier");
        lVar.g(writer, modelError.b);
        writer.l("code");
        this.c.g(writer, modelError.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(32, "GeneratedJsonAdapter(ModelError)", "toString(...)");
    }
}
