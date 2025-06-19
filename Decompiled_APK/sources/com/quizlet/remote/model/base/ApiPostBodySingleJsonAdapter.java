package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Type;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ApiPostBodySingleJsonAdapter<T> extends l {
    public final c a;
    public final l b;

    public ApiPostBodySingleJsonAdapter(@NotNull D moshi, @NotNull Type[] types) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        Intrinsics.checkNotNullParameter(types, "types");
        if (types.length != 1) {
            String str = "TypeVariable mismatch: Expecting 1 type for generic type variables [T], but received " + types.length;
            Intrinsics.checkNotNullExpressionValue(str, "toString(...)");
            throw new IllegalArgumentException(str.toString());
        }
        c cVarB = c.b("data");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(types[0], M.a, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Object objA = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (objA = this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("data_", "data", reader);
            }
        }
        reader.i();
        if (objA != null) {
            return new ApiPostBodySingle(objA);
        }
        throw com.squareup.moshi.internal.b.e("data_", "data", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiPostBodySingle apiPostBodySingle = (ApiPostBodySingle) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiPostBodySingle == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, apiPostBodySingle.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(ApiPostBodySingle)", "toString(...)");
    }
}
