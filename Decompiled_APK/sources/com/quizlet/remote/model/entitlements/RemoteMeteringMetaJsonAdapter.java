package com.quizlet.remote.model.entitlements;

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
/* loaded from: classes3.dex */
public final class RemoteMeteringMetaJsonAdapter extends l {
    public final c a;
    public final l b;

    public RemoteMeteringMetaJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("numEvents", "threshold");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(Integer.TYPE, M.a, "numEvents");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw b.k("numEvents", "numEvents", reader);
                    }
                } else if (iK0 == 1 && (num2 = (Integer) lVar.a(reader)) == null) {
                    throw b.k("threshold", "threshold", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (num == null) {
            throw b.e("numEvents", "numEvents", reader);
        }
        int iIntValue = num.intValue();
        if (num2 != null) {
            return new RemoteMeteringMeta(iIntValue, num2.intValue());
        }
        throw b.e("threshold", "threshold", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteMeteringMeta remoteMeteringMeta = (RemoteMeteringMeta) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteMeteringMeta == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("numEvents");
        Integer numValueOf = Integer.valueOf(remoteMeteringMeta.a);
        l lVar = this.b;
        lVar.g(writer, numValueOf);
        writer.l("threshold");
        lVar.g(writer, Integer.valueOf(remoteMeteringMeta.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(RemoteMeteringMeta)", "toString(...)");
    }
}
