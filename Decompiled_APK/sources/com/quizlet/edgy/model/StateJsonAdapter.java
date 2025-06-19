package com.quizlet.edgy.model;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StateJsonAdapter extends l {
    public final c a;
    public final l b;

    public StateJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("code", "name");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "code");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw b.k("code", "code", reader);
                    }
                } else if (iK0 == 1 && (str2 = (String) lVar.a(reader)) == null) {
                    throw b.k("name", "name", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw b.e("code", "code", reader);
        }
        if (str2 != null) {
            return new State(str, str2);
        }
        throw b.e("name", "name", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        State state = (State) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (state == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("code");
        l lVar = this.b;
        lVar.g(writer, state.a);
        writer.l("name");
        lVar.g(writer, state.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(27, "GeneratedJsonAdapter(State)", "toString(...)");
    }
}
