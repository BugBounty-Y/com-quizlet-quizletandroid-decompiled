package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ApiThreeWrapperJsonAdapter<T extends ApiResponse> extends l {
    public final c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public ApiThreeWrapperJsonAdapter(@NotNull D moshi, @NotNull Type[] types) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        Intrinsics.checkNotNullParameter(types, "types");
        if (types.length != 1) {
            String str = "TypeVariable mismatch: Expecting 1 type for generic type variables [T], but received " + types.length;
            Intrinsics.checkNotNullExpressionValue(str, "toString(...)");
            throw new IllegalArgumentException(str.toString());
        }
        c cVarB = c.b("responses", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, types[0]);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "responses");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(ApiError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        ApiError apiError = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                i &= -2;
            } else if (iK0 == 1) {
                apiError = (ApiError) this.c.a(reader);
                i &= -3;
            }
        }
        reader.i();
        if (i == -4) {
            return new ApiThreeWrapper(list, apiError);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = ApiThreeWrapper.class.getDeclaredConstructor(List.class, ApiError.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            Intrinsics.e(declaredConstructor, "null cannot be cast to non-null type java.lang.reflect.Constructor<com.quizlet.remote.model.base.ApiThreeWrapper<T of com.quizlet.remote.model.base.ApiThreeWrapperJsonAdapter>>");
            this.d = declaredConstructor;
        }
        Object objNewInstance = declaredConstructor.newInstance(list, apiError, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (ApiThreeWrapper) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiThreeWrapper == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("responses");
        this.b.g(writer, apiThreeWrapper.a);
        writer.l("error");
        this.c.g(writer, apiThreeWrapper.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(ApiThreeWrapper)", "toString(...)");
    }
}
