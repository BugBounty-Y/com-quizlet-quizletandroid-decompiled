package com.quizlet.remote.model.school.memberships;

import com.airbnb.lottie.parser.moshi.c;
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
public final class RemoteNewSchoolMembershipJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteNewSchoolMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b(DBGroupFields.Names.SCHOOL_ID, "relationshipType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, DBGroupFields.Names.SCHOOL_ID);
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
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw b.k(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                }
            } else if (iK0 == 1 && (num = (Integer) this.c.a(reader)) == null) {
                throw b.k("relationshipType", "relationshipType", reader);
            }
        }
        reader.i();
        if (l == null) {
            throw b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
        }
        long jLongValue = l.longValue();
        if (num != null) {
            return new RemoteNewSchoolMembership(num.intValue(), jLongValue);
        }
        throw b.e("relationshipType", "relationshipType", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteNewSchoolMembership remoteNewSchoolMembership = (RemoteNewSchoolMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteNewSchoolMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        this.b.g(writer, Long.valueOf(remoteNewSchoolMembership.a));
        writer.l("relationshipType");
        this.c.g(writer, Integer.valueOf(remoteNewSchoolMembership.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(RemoteNewSchoolMembership)", "toString(...)");
    }
}
