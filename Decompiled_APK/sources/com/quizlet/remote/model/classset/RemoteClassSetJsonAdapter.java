package com.quizlet.remote.model.classset;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
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
public final class RemoteClassSetJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteClassSetJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("clientId", "setId", DBGroupMembershipFields.Names.CLASS_ID, "userId", "folderId", DBGroupFolderFields.Names.CAN_EDIT, "timestamp", "lastModified", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "isDeleted", "isDirty");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "localId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "setId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.class, m, DBGroupFolderFields.Names.CAN_EDIT);
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Long l4 = null;
        Long l5 = null;
        Boolean bool = null;
        Long l6 = null;
        Long l7 = null;
        Long l8 = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.c;
            Long l9 = l;
            l lVar2 = this.d;
            Long l10 = l2;
            l lVar3 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l9;
                    l2 = l10;
                case 0:
                    l3 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 1:
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw b.k("setId", "setId", reader);
                    }
                    l2 = l10;
                case 2:
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw b.k(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
                    }
                    l = l9;
                case 3:
                    l4 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 4:
                    l5 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 5:
                    bool = (Boolean) lVar2.a(reader);
                    l = l9;
                    l2 = l10;
                case 6:
                    l6 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 7:
                    l7 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 8:
                    l8 = (Long) lVar3.a(reader);
                    l = l9;
                    l2 = l10;
                case 9:
                    bool2 = (Boolean) lVar2.a(reader);
                    l = l9;
                    l2 = l10;
                case 10:
                    bool3 = (Boolean) lVar2.a(reader);
                    l = l9;
                    l2 = l10;
                default:
                    l = l9;
                    l2 = l10;
            }
        }
        Long l11 = l;
        Long l12 = l2;
        reader.i();
        if (l11 == null) {
            throw b.e("setId", "setId", reader);
        }
        long jLongValue = l11.longValue();
        if (l12 != null) {
            return new RemoteClassSet(l3, jLongValue, l12.longValue(), l4, l5, bool, l6, l7, l8, bool2, bool3);
        }
        throw b.e(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteClassSet remoteClassSet = (RemoteClassSet) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteClassSet == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("clientId");
        l lVar = this.b;
        lVar.g(writer, remoteClassSet.a);
        writer.l("setId");
        Long lValueOf = Long.valueOf(remoteClassSet.b);
        l lVar2 = this.c;
        lVar2.g(writer, lValueOf);
        writer.l(DBGroupMembershipFields.Names.CLASS_ID);
        Z.k(remoteClassSet.c, lVar2, writer, "userId");
        lVar.g(writer, remoteClassSet.d);
        writer.l("folderId");
        lVar.g(writer, remoteClassSet.e);
        writer.l(DBGroupFolderFields.Names.CAN_EDIT);
        l lVar3 = this.d;
        lVar3.g(writer, remoteClassSet.f);
        writer.l("timestamp");
        lVar.g(writer, remoteClassSet.g);
        writer.l("lastModified");
        lVar.g(writer, remoteClassSet.h);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        lVar.g(writer, remoteClassSet.i);
        writer.l("isDeleted");
        lVar3.g(writer, remoteClassSet.j);
        writer.l("isDirty");
        lVar3.g(writer, remoteClassSet.k);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteClassSet)", "toString(...)");
    }
}
