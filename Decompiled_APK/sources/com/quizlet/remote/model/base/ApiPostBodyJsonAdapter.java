package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Type;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ApiPostBodyJsonAdapter<T> extends l {
    public final c a;
    public final l b;

    public ApiPostBodyJsonAdapter(@NotNull D moshi, @NotNull Type[] types) {
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
        l lVarA = moshi.a(H.f(List.class, types[0]), M.a, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (list = (List) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("data_", "data", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new ApiPostBody(list);
        }
        throw com.squareup.moshi.internal.b.e("data_", "data", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiPostBody apiPostBody = (ApiPostBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiPostBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, apiPostBody.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(ApiPostBody)", "toString(...)");
    }
}
