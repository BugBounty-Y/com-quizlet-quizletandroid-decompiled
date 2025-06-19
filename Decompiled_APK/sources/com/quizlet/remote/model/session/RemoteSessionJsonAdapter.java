package com.quizlet.remote.model.session;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class RemoteSessionJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public RemoteSessionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "personId", DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_TYPE, "timestamp", "endedTimestamp", DBUserFields.Names.USER_UPGRADE_TYPE, DBSessionFields.Names.SCORE, "hidden", DBSessionFields.Names.SELECTED_TERMS_ONLY, "lastModified");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, DBSessionFields.Names.ITEM_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "endedTimestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.class, m, "hidden");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Integer num = null;
        Long l4 = null;
        Integer num2 = null;
        Long l5 = null;
        Long l6 = null;
        Boolean bool = null;
        Boolean bool2 = null;
        Long l7 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.c;
            Long l8 = l;
            l lVar2 = this.e;
            Long l9 = l2;
            l lVar3 = this.d;
            Long l10 = l3;
            l lVar4 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 0:
                    l = (Long) lVar4.a(reader);
                    if (l == null) {
                        throw b.k("id", "id", reader);
                    }
                    l2 = l9;
                    l3 = l10;
                case 1:
                    l2 = (Long) lVar4.a(reader);
                    if (l2 == null) {
                        throw b.k("personId", "personId", reader);
                    }
                    l = l8;
                    l3 = l10;
                case 2:
                    l3 = (Long) lVar4.a(reader);
                    if (l3 == null) {
                        throw b.k(DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, reader);
                    }
                    l = l8;
                    l2 = l9;
                case 3:
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw b.k(DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, reader);
                    }
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 4:
                    l4 = (Long) lVar4.a(reader);
                    if (l4 == null) {
                        throw b.k("timestamp", "timestamp", reader);
                    }
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 5:
                    l5 = (Long) lVar3.a(reader);
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 6:
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw b.k(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                    }
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 7:
                    l6 = (Long) lVar3.a(reader);
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 8:
                    bool = (Boolean) lVar2.a(reader);
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 9:
                    bool2 = (Boolean) lVar2.a(reader);
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                case 10:
                    l7 = (Long) lVar3.a(reader);
                    l = l8;
                    l2 = l9;
                    l3 = l10;
                default:
                    l = l8;
                    l2 = l9;
                    l3 = l10;
            }
        }
        Long l11 = l;
        Long l12 = l2;
        Long l13 = l3;
        reader.i();
        Integer num3 = num2;
        if (l11 == null) {
            throw b.e("id", "id", reader);
        }
        long jLongValue = l11.longValue();
        if (l12 == null) {
            throw b.e("personId", "personId", reader);
        }
        long jLongValue2 = l12.longValue();
        if (l13 == null) {
            throw b.e(DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, reader);
        }
        long jLongValue3 = l13.longValue();
        if (num == null) {
            throw b.e(DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, reader);
        }
        int iIntValue = num.intValue();
        if (l4 == null) {
            throw b.e("timestamp", "timestamp", reader);
        }
        long jLongValue4 = l4.longValue();
        if (num3 != null) {
            return new RemoteSession(jLongValue, jLongValue2, jLongValue3, iIntValue, jLongValue4, l5, num3.intValue(), l6, bool, bool2, l7);
        }
        throw b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSession remoteSession = (RemoteSession) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSession == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(remoteSession.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("personId");
        Z.k(remoteSession.b, lVar, writer, DBSessionFields.Names.ITEM_ID);
        Z.k(remoteSession.c, lVar, writer, DBSessionFields.Names.ITEM_TYPE);
        Integer numValueOf = Integer.valueOf(remoteSession.d);
        l lVar2 = this.c;
        lVar2.g(writer, numValueOf);
        writer.l("timestamp");
        Z.k(remoteSession.e, lVar, writer, "endedTimestamp");
        l lVar3 = this.d;
        lVar3.g(writer, remoteSession.f);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        AbstractC4178x.p(remoteSession.g, lVar2, writer, DBSessionFields.Names.SCORE);
        lVar3.g(writer, remoteSession.h);
        writer.l("hidden");
        l lVar4 = this.e;
        lVar4.g(writer, remoteSession.i);
        writer.l(DBSessionFields.Names.SELECTED_TERMS_ONLY);
        lVar4.g(writer, remoteSession.j);
        writer.l("lastModified");
        lVar3.g(writer, remoteSession.k);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(35, "GeneratedJsonAdapter(RemoteSession)", "toString(...)");
    }
}
