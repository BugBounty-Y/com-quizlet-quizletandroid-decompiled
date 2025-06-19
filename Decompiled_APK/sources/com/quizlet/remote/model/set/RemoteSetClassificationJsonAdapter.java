package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class RemoteSetClassificationJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteSetClassificationJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", DBSessionFields.Names.SCORE, "lineage");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Double.TYPE, m, DBSessionFields.Names.SCORE);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSetLineage.class), m, "lineage");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Double d = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("id", "id", reader);
                }
            } else if (iK0 == 1) {
                d = (Double) this.c.a(reader);
                if (d == null) {
                    throw com.squareup.moshi.internal.b.k(DBSessionFields.Names.SCORE, DBSessionFields.Names.SCORE, reader);
                }
            } else if (iK0 == 2 && (list = (List) this.d.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("lineage", "lineage", reader);
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (d == null) {
            throw com.squareup.moshi.internal.b.e(DBSessionFields.Names.SCORE, DBSessionFields.Names.SCORE, reader);
        }
        double dDoubleValue = d.doubleValue();
        if (list != null) {
            return new RemoteSetClassification(jLongValue, dDoubleValue, list);
        }
        throw com.squareup.moshi.internal.b.e("lineage", "lineage", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSetClassification remoteSetClassification = (RemoteSetClassification) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSetClassification == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteSetClassification.a));
        writer.l(DBSessionFields.Names.SCORE);
        this.c.g(writer, Double.valueOf(remoteSetClassification.b));
        writer.l("lineage");
        this.d.g(writer, remoteSetClassification.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(45, "GeneratedJsonAdapter(RemoteSetClassification)", "toString(...)");
    }
}
