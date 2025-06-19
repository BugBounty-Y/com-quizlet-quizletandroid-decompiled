package com.quizlet.remote.model.school.memberships;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
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
public final class RemoteSchoolMembershipJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteSchoolMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("userId", DBGroupFields.Names.SCHOOL_ID, "relationshipType", "lastModified");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "relationshipType");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
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
                        throw b.k("userId", "userId", reader);
                    }
                } else if (iK0 == 1) {
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw b.k(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                    }
                } else if (iK0 == 2) {
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw b.k("relationshipType", "relationshipType", reader);
                    }
                } else if (iK0 == 3 && (l3 = (Long) lVar.a(reader)) == null) {
                    throw b.k("lastModified", "lastModified", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Long l4 = l;
        if (l4 == null) {
            throw b.e("userId", "userId", reader);
        }
        long jLongValue = l4.longValue();
        if (l2 == null) {
            throw b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
        }
        long jLongValue2 = l2.longValue();
        if (num == null) {
            throw b.e("relationshipType", "relationshipType", reader);
        }
        int iIntValue = num.intValue();
        if (l3 != null) {
            return new RemoteSchoolMembership(jLongValue, jLongValue2, iIntValue, l3.longValue());
        }
        throw b.e("lastModified", "lastModified", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSchoolMembership remoteSchoolMembership = (RemoteSchoolMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSchoolMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("userId");
        Long lValueOf = Long.valueOf(remoteSchoolMembership.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        Z.k(remoteSchoolMembership.b, lVar, writer, "relationshipType");
        this.c.g(writer, Integer.valueOf(remoteSchoolMembership.c));
        writer.l("lastModified");
        lVar.g(writer, Long.valueOf(remoteSchoolMembership.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(RemoteSchoolMembership)", "toString(...)");
    }
}
