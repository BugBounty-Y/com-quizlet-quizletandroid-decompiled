package com.quizlet.remote.model.classmembership;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
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
public final class RemoteClassMembershipJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteClassMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("userId", DBGroupMembershipFields.Names.CLASS_ID, "lastVisited", "level", "receiveEmail", "timestamp", "lastModified");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "lastVisitedSec");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.TYPE, m, "receiveEmail");
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
        Integer num2 = null;
        Boolean bool = null;
        Integer num3 = null;
        Integer num4 = null;
        while (true) {
            Long l3 = l;
            Long l4 = l2;
            Integer num5 = num;
            Integer num6 = num2;
            if (!reader.l()) {
                Boolean bool2 = bool;
                Integer num7 = num3;
                reader.i();
                if (l3 == null) {
                    throw b.e("userId", "userId", reader);
                }
                long jLongValue = l3.longValue();
                if (l4 == null) {
                    throw b.e(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
                }
                long jLongValue2 = l4.longValue();
                if (num5 == null) {
                    throw b.e("lastVisitedSec", "lastVisited", reader);
                }
                int iIntValue = num5.intValue();
                if (num6 == null) {
                    throw b.e("level", "level", reader);
                }
                int iIntValue2 = num6.intValue();
                if (bool2 == null) {
                    throw b.e("receiveEmail", "receiveEmail", reader);
                }
                boolean zBooleanValue = bool2.booleanValue();
                if (num7 == null) {
                    throw b.e("timestampSec", "timestamp", reader);
                }
                int iIntValue3 = num7.intValue();
                if (num4 != null) {
                    return new RemoteClassMembership(jLongValue, jLongValue2, iIntValue, iIntValue2, zBooleanValue, iIntValue3, num4.intValue());
                }
                throw b.e("lastModifiedSec", "lastModified", reader);
            }
            int iK0 = reader.k0(this.a);
            Boolean bool3 = bool;
            l lVar = this.b;
            Integer num8 = num3;
            l lVar2 = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l3;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
                case 0:
                    Long l5 = (Long) lVar.a(reader);
                    if (l5 == null) {
                        throw b.k("userId", "userId", reader);
                    }
                    l = l5;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
                case 1:
                    Long l6 = (Long) lVar.a(reader);
                    if (l6 == null) {
                        throw b.k(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
                    }
                    l2 = l6;
                    l = l3;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
                case 2:
                    num = (Integer) lVar2.a(reader);
                    if (num == null) {
                        throw b.k("lastVisitedSec", "lastVisited", reader);
                    }
                    l = l3;
                    l2 = l4;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
                case 3:
                    num2 = (Integer) lVar2.a(reader);
                    if (num2 == null) {
                        throw b.k("level", "level", reader);
                    }
                    l = l3;
                    l2 = l4;
                    num = num5;
                    bool = bool3;
                    num3 = num8;
                case 4:
                    bool = (Boolean) this.d.a(reader);
                    if (bool == null) {
                        throw b.k("receiveEmail", "receiveEmail", reader);
                    }
                    l = l3;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    num3 = num8;
                case 5:
                    num3 = (Integer) lVar2.a(reader);
                    if (num3 == null) {
                        throw b.k("timestampSec", "timestamp", reader);
                    }
                    l = l3;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                case 6:
                    num4 = (Integer) lVar2.a(reader);
                    if (num4 == null) {
                        throw b.k("lastModifiedSec", "lastModified", reader);
                    }
                    l = l3;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
                default:
                    l = l3;
                    l2 = l4;
                    num = num5;
                    num2 = num6;
                    bool = bool3;
                    num3 = num8;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteClassMembership remoteClassMembership = (RemoteClassMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteClassMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("userId");
        Long lValueOf = Long.valueOf(remoteClassMembership.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBGroupMembershipFields.Names.CLASS_ID);
        Z.k(remoteClassMembership.b, lVar, writer, "lastVisited");
        Integer numValueOf = Integer.valueOf(remoteClassMembership.c);
        l lVar2 = this.c;
        lVar2.g(writer, numValueOf);
        writer.l("level");
        AbstractC4178x.p(remoteClassMembership.d, lVar2, writer, "receiveEmail");
        this.d.g(writer, Boolean.valueOf(remoteClassMembership.e));
        writer.l("timestamp");
        AbstractC4178x.p(remoteClassMembership.f, lVar2, writer, "lastModified");
        lVar2.g(writer, Integer.valueOf(remoteClassMembership.g));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(RemoteClassMembership)", "toString(...)");
    }
}
