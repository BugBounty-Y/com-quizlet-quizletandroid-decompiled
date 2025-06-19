package com.quizlet.remote.model.selectedterm;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteSelectedTermJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteSelectedTermJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("termId", "personId", "setId", "source");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "termId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "source");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("termId", "termId", reader);
                    }
                } else if (iK0 == 1) {
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                    }
                } else if (iK0 == 2) {
                    l3 = (Long) lVar.a(reader);
                    if (l3 == null) {
                        throw com.squareup.moshi.internal.b.k("setId", "setId", reader);
                    }
                } else if (iK0 == 3 && (num = (Integer) this.c.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("source", "source", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Long l4 = l;
        if (l4 == null) {
            throw com.squareup.moshi.internal.b.e("termId", "termId", reader);
        }
        long jLongValue = l4.longValue();
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
        }
        long jLongValue2 = l2.longValue();
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("setId", "setId", reader);
        }
        long jLongValue3 = l3.longValue();
        if (num != null) {
            return new RemoteSelectedTerm(jLongValue, jLongValue2, num.intValue(), jLongValue3);
        }
        throw com.squareup.moshi.internal.b.e("source", "source", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSelectedTerm remoteSelectedTerm = (RemoteSelectedTerm) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSelectedTerm == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("termId");
        Long lValueOf = Long.valueOf(remoteSelectedTerm.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("personId");
        Z.k(remoteSelectedTerm.b, lVar, writer, "setId");
        Z.k(remoteSelectedTerm.c, lVar, writer, "source");
        this.c.g(writer, Integer.valueOf(remoteSelectedTerm.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(RemoteSelectedTerm)", "toString(...)");
    }
}
