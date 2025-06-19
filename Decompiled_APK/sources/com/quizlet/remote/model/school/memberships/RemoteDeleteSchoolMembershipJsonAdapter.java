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
public final class RemoteDeleteSchoolMembershipJsonAdapter extends l {
    public final c a;
    public final l b;

    public RemoteDeleteSchoolMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("userId", DBGroupFields.Names.SCHOOL_ID);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(Long.TYPE, M.a, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw b.k("userId", "userId", reader);
                    }
                } else if (iK0 == 1 && (l2 = (Long) lVar.a(reader)) == null) {
                    throw b.k(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (l == null) {
            throw b.e("userId", "userId", reader);
        }
        long jLongValue = l.longValue();
        if (l2 != null) {
            return new RemoteDeleteSchoolMembership(jLongValue, l2.longValue());
        }
        throw b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteDeleteSchoolMembership remoteDeleteSchoolMembership = (RemoteDeleteSchoolMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteDeleteSchoolMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("userId");
        Long lValueOf = Long.valueOf(remoteDeleteSchoolMembership.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        lVar.g(writer, Long.valueOf(remoteDeleteSchoolMembership.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(50, "GeneratedJsonAdapter(RemoteDeleteSchoolMembership)", "toString(...)");
    }
}
