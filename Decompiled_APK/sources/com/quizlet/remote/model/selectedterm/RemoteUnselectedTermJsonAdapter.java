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
public final class RemoteUnselectedTermJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteUnselectedTermJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("termId", "personId", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "termId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Boolean bool = null;
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
                } else if (iK0 == 2 && (bool = (Boolean) this.c.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Long l3 = l;
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("termId", "termId", reader);
        }
        long jLongValue = l3.longValue();
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
        }
        long jLongValue2 = l2.longValue();
        if (bool != null) {
            return new RemoteUnselectedTerm(jLongValue, jLongValue2, bool.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("isDeleted", "isDeleted", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteUnselectedTerm remoteUnselectedTerm = (RemoteUnselectedTerm) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteUnselectedTerm == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("termId");
        Long lValueOf = Long.valueOf(remoteUnselectedTerm.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("personId");
        Z.k(remoteUnselectedTerm.b, lVar, writer, "isDeleted");
        this.c.g(writer, Boolean.valueOf(remoteUnselectedTerm.c));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(RemoteUnselectedTerm)", "toString(...)");
    }
}
