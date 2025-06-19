package com.quizlet.remote.model.progress;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;
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
public final class RemoteProgressResetJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteProgressResetJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("personId", DBProgressResetFields.Names.CONTAINER_ID, DBProgressResetFields.Names.CONTAINER_TYPE, "resetTime");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "personId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, DBProgressResetFields.Names.CONTAINER_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "resetTime");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Integer num = null;
        Long l3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                    }
                } else if (iK0 == 1) {
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBProgressResetFields.Names.CONTAINER_ID, DBProgressResetFields.Names.CONTAINER_ID, reader);
                    }
                } else if (iK0 == 2) {
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k(DBProgressResetFields.Names.CONTAINER_TYPE, DBProgressResetFields.Names.CONTAINER_TYPE, reader);
                    }
                } else if (iK0 == 3) {
                    l3 = (Long) this.d.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
        }
        long jLongValue = l.longValue();
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e(DBProgressResetFields.Names.CONTAINER_ID, DBProgressResetFields.Names.CONTAINER_ID, reader);
        }
        long jLongValue2 = l2.longValue();
        if (num != null) {
            return new RemoteProgressReset(jLongValue, jLongValue2, num.intValue(), l3);
        }
        throw com.squareup.moshi.internal.b.e(DBProgressResetFields.Names.CONTAINER_TYPE, DBProgressResetFields.Names.CONTAINER_TYPE, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteProgressReset remoteProgressReset = (RemoteProgressReset) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteProgressReset == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("personId");
        Long lValueOf = Long.valueOf(remoteProgressReset.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBProgressResetFields.Names.CONTAINER_ID);
        Z.k(remoteProgressReset.b, lVar, writer, DBProgressResetFields.Names.CONTAINER_TYPE);
        this.c.g(writer, Integer.valueOf(remoteProgressReset.c));
        writer.l("resetTime");
        this.d.g(writer, remoteProgressReset.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(RemoteProgressReset)", "toString(...)");
    }
}
