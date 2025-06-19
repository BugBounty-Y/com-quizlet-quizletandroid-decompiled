package com.quizlet.edgy.model;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AllCountriesJsonAdapter extends l {
    public final c a;
    public final l b;

    public AllCountriesJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("allCountries");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(Map.class, String.class, String.class), M.a, "allCountries");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Map map = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (map = (Map) this.b.a(reader)) == null) {
                throw b.k("allCountries", "allCountries", reader);
            }
        }
        reader.i();
        if (map != null) {
            return new AllCountries(map);
        }
        throw b.e("allCountries", "allCountries", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        AllCountries allCountries = (AllCountries) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (allCountries == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("allCountries");
        this.b.g(writer, allCountries.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(AllCountries)", "toString(...)");
    }
}
