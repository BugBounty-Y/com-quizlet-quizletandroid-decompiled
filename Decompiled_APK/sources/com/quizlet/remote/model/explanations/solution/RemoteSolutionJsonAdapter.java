package com.quizlet.remote.model.explanations.solution;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteSolutionJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteSolutionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("steps", "totalSteps");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteSolutionStep.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "steps");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "totalSteps");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw b.k("steps", "steps", reader);
                }
            } else if (iK0 == 1 && (num = (Integer) this.c.a(reader)) == null) {
                throw b.k("totalSteps", "totalSteps", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw b.e("steps", "steps", reader);
        }
        if (num != null) {
            return new RemoteSolution(list, num.intValue());
        }
        throw b.e("totalSteps", "totalSteps", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSolution remoteSolution = (RemoteSolution) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSolution == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("steps");
        this.b.g(writer, remoteSolution.a);
        writer.l("totalSteps");
        this.c.g(writer, Integer.valueOf(remoteSolution.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteSolution)", "toString(...)");
    }
}
