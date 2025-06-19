package com.quizlet.remote.model.classfolder;

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
public final class RemoteClassFolderJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteClassFolderJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("clientId", "folderId", DBGroupMembershipFields.Names.CLASS_ID, DBGroupFolderFields.Names.CAN_EDIT, "addedTimestamp", "lastModified", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "isDeleted", "isDirty");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "localId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "folderId");
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
        Boolean bool = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.c;
            l lVar2 = this.d;
            Long l7 = l;
            l lVar3 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l3 = (Long) lVar3.a(reader);
                    break;
                case 1:
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw b.k("folderId", "folderId", reader);
                    }
                    continue;
                case 2:
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw b.k(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
                    }
                    break;
                case 3:
                    bool = (Boolean) lVar2.a(reader);
                    break;
                case 4:
                    l4 = (Long) lVar3.a(reader);
                    break;
                case 5:
                    l5 = (Long) lVar3.a(reader);
                    break;
                case 6:
                    l6 = (Long) lVar3.a(reader);
                    break;
                case 7:
                    bool2 = (Boolean) lVar2.a(reader);
                    break;
                case 8:
                    bool3 = (Boolean) lVar2.a(reader);
                    break;
            }
            l = l7;
        }
        Long l8 = l;
        reader.i();
        Long l9 = l2;
        if (l8 == null) {
            throw b.e("folderId", "folderId", reader);
        }
        long jLongValue = l8.longValue();
        if (l9 != null) {
            return new RemoteClassFolder(l3, jLongValue, l9.longValue(), bool, l4, l5, l6, bool2, bool3);
        }
        throw b.e(DBGroupMembershipFields.Names.CLASS_ID, DBGroupMembershipFields.Names.CLASS_ID, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteClassFolder remoteClassFolder = (RemoteClassFolder) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteClassFolder == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("clientId");
        l lVar = this.b;
        lVar.g(writer, remoteClassFolder.a);
        writer.l("folderId");
        Long lValueOf = Long.valueOf(remoteClassFolder.b);
        l lVar2 = this.c;
        lVar2.g(writer, lValueOf);
        writer.l(DBGroupMembershipFields.Names.CLASS_ID);
        Z.k(remoteClassFolder.c, lVar2, writer, DBGroupFolderFields.Names.CAN_EDIT);
        l lVar3 = this.d;
        lVar3.g(writer, remoteClassFolder.d);
        writer.l("addedTimestamp");
        lVar.g(writer, remoteClassFolder.e);
        writer.l("lastModified");
        lVar.g(writer, remoteClassFolder.f);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        lVar.g(writer, remoteClassFolder.g);
        writer.l("isDeleted");
        lVar3.g(writer, remoteClassFolder.h);
        writer.l("isDirty");
        lVar3.g(writer, remoteClassFolder.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(RemoteClassFolder)", "toString(...)");
    }
}
