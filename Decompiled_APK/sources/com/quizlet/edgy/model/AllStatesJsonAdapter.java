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
public final class AllStatesJsonAdapter extends l {
    public final c a;
    public final l b;

    public AllStatesJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("allStates");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(Map.class, String.class, String.class), M.a, "allStates");
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
                throw b.k("allStates", "allStates", reader);
            }
        }
        reader.i();
        if (map != null) {
            return new AllStates(map);
        }
        throw b.e("allStates", "allStates", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        AllStates allStates = (AllStates) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (allStates == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("allStates");
        this.b.g(writer, allStates.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(31, "GeneratedJsonAdapter(AllStates)", "toString(...)");
    }
}
