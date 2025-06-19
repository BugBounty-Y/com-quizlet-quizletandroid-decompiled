package com.quizlet.remote.model.explanations.solution;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class RemoteSolutionStepJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteSolutionStepJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("isResult", "stepNumber", "columns");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Boolean.TYPE, m, "isResult");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "stepNumber");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSolutionColumn.class), m, "columns");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        Integer num = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw b.k("isResult", "isResult", reader);
                }
            } else if (iK0 == 1) {
                num = (Integer) this.c.a(reader);
                if (num == null) {
                    throw b.k("stepNumber", "stepNumber", reader);
                }
            } else if (iK0 == 2 && (list = (List) this.d.a(reader)) == null) {
                throw b.k("columns", "columns", reader);
            }
        }
        reader.i();
        if (bool == null) {
            throw b.e("isResult", "isResult", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (num == null) {
            throw b.e("stepNumber", "stepNumber", reader);
        }
        int iIntValue = num.intValue();
        if (list != null) {
            return new RemoteSolutionStep(zBooleanValue, iIntValue, list);
        }
        throw b.e("columns", "columns", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSolutionStep remoteSolutionStep = (RemoteSolutionStep) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSolutionStep == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("isResult");
        this.b.g(writer, Boolean.valueOf(remoteSolutionStep.a));
        writer.l("stepNumber");
        this.c.g(writer, Integer.valueOf(remoteSolutionStep.b));
        writer.l("columns");
        this.d.g(writer, remoteSolutionStep.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(RemoteSolutionStep)", "toString(...)");
    }
}
