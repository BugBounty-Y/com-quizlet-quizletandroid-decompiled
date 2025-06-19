package com.quizlet.remote.model.qclass;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteClassJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public volatile Constructor g;

    public RemoteClassJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "title", OTUXParamsKeys.OT_UX_DESCRIPTION, DBGroupFields.Names.SCHOOL_ID, "restrictsPosting", "membersCanPost", "membersCanInvite", "creatorId", DBGroupFields.Names.AUTO_JOIN_LINK, "_numMembers", DBFolderFields.Names.NUM_SETS, "timestamp", "lastModified");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.TYPE, m, "restrictsPosting");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, DBGroupFields.Names.AUTO_JOIN_LINK);
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Long.class, m, "timestampSec");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Long l;
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        Long l2 = null;
        String str = null;
        String str2 = null;
        Long l3 = null;
        Boolean bool = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Long l7 = null;
        Long l8 = null;
        String str3 = null;
        while (true) {
            Long l9 = l2;
            String str4 = str;
            String str5 = str2;
            Long l10 = l3;
            Boolean bool4 = bool;
            Boolean bool5 = bool2;
            Boolean bool6 = bool3;
            Long l11 = l4;
            Long l12 = l5;
            Long l13 = l6;
            if (!reader.l()) {
                Long l14 = l7;
                reader.i();
                if (i == -6401) {
                    if (l9 == null) {
                        throw b.e("id", "id", reader);
                    }
                    long jLongValue = l9.longValue();
                    if (str4 == null) {
                        throw b.e("title", "title", reader);
                    }
                    if (str5 == null) {
                        throw b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    if (l10 == null) {
                        throw b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                    }
                    long jLongValue2 = l10.longValue();
                    if (bool4 == null) {
                        throw b.e("restrictsPosting", "restrictsPosting", reader);
                    }
                    boolean zBooleanValue = bool4.booleanValue();
                    if (bool5 == null) {
                        throw b.e("membersCanPost", "membersCanPost", reader);
                    }
                    boolean zBooleanValue2 = bool5.booleanValue();
                    if (bool6 == null) {
                        throw b.e("membersCanInvite", "membersCanInvite", reader);
                    }
                    boolean zBooleanValue3 = bool6.booleanValue();
                    if (l11 == null) {
                        throw b.e("creatorId", "creatorId", reader);
                    }
                    Long l15 = l8;
                    long jLongValue3 = l11.longValue();
                    if (l12 == null) {
                        throw b.e("numMembers", "_numMembers", reader);
                    }
                    long jLongValue4 = l12.longValue();
                    if (l13 != null) {
                        return new RemoteClass(jLongValue, str4, str5, jLongValue2, zBooleanValue, zBooleanValue2, zBooleanValue3, jLongValue3, str3, jLongValue4, l13.longValue(), l14, l15);
                    }
                    throw b.e("numSets", DBFolderFields.Names.NUM_SETS, reader);
                }
                int i2 = i;
                Constructor declaredConstructor = this.g;
                if (declaredConstructor == null) {
                    Class cls = b.c;
                    Class cls2 = Long.TYPE;
                    Class cls3 = Boolean.TYPE;
                    Class[] clsArr = {cls2, String.class, String.class, cls2, cls3, cls3, cls3, cls2, String.class, cls2, cls2, Long.class, Long.class, Integer.TYPE, cls};
                    l = l14;
                    declaredConstructor = RemoteClass.class.getDeclaredConstructor(clsArr);
                    this.g = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    l = l14;
                }
                if (l9 == null) {
                    throw b.e("id", "id", reader);
                }
                if (str4 == null) {
                    throw b.e("title", "title", reader);
                }
                if (str5 == null) {
                    throw b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (l10 == null) {
                    throw b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                }
                if (bool4 == null) {
                    throw b.e("restrictsPosting", "restrictsPosting", reader);
                }
                if (bool5 == null) {
                    throw b.e("membersCanPost", "membersCanPost", reader);
                }
                if (bool6 == null) {
                    throw b.e("membersCanInvite", "membersCanInvite", reader);
                }
                if (l11 == null) {
                    throw b.e("creatorId", "creatorId", reader);
                }
                if (l12 == null) {
                    throw b.e("numMembers", "_numMembers", reader);
                }
                if (l13 == null) {
                    throw b.e("numSets", DBFolderFields.Names.NUM_SETS, reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(l9, str4, str5, l10, bool4, bool5, bool6, l11, str3, l12, l13, l, l8, Integer.valueOf(i2), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (RemoteClass) objNewInstance;
            }
            Long l16 = l7;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 0:
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw b.k("id", "id", reader);
                    }
                    l7 = l16;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 1:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw b.k("title", "title", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 2:
                    str2 = (String) this.c.a(reader);
                    if (str2 == null) {
                        throw b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 3:
                    l3 = (Long) this.b.a(reader);
                    if (l3 == null) {
                        throw b.k(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 4:
                    bool = (Boolean) this.d.a(reader);
                    if (bool == null) {
                        throw b.k("restrictsPosting", "restrictsPosting", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 5:
                    bool2 = (Boolean) this.d.a(reader);
                    if (bool2 == null) {
                        throw b.k("membersCanPost", "membersCanPost", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 6:
                    bool3 = (Boolean) this.d.a(reader);
                    if (bool3 == null) {
                        throw b.k("membersCanInvite", "membersCanInvite", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 7:
                    l4 = (Long) this.b.a(reader);
                    if (l4 == null) {
                        throw b.k("creatorId", "creatorId", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l5 = l12;
                    l6 = l13;
                case 8:
                    str3 = (String) this.e.a(reader);
                    i &= -257;
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 9:
                    l5 = (Long) this.b.a(reader);
                    if (l5 == null) {
                        throw b.k("numMembers", "_numMembers", reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l6 = l13;
                case 10:
                    l6 = (Long) this.b.a(reader);
                    if (l6 == null) {
                        throw b.k("numSets", DBFolderFields.Names.NUM_SETS, reader);
                    }
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                case 11:
                    l7 = (Long) this.f.a(reader);
                    i &= -2049;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                case 12:
                    l8 = (Long) this.f.a(reader);
                    i &= -4097;
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
                default:
                    l7 = l16;
                    l2 = l9;
                    str = str4;
                    str2 = str5;
                    l3 = l10;
                    bool = bool4;
                    bool2 = bool5;
                    bool3 = bool6;
                    l4 = l11;
                    l5 = l12;
                    l6 = l13;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteClass remoteClass = (RemoteClass) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteClass == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(remoteClass.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("title");
        l lVar2 = this.c;
        lVar2.g(writer, remoteClass.b);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar2.g(writer, remoteClass.c);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        Z.k(remoteClass.d, lVar, writer, "restrictsPosting");
        Boolean boolValueOf = Boolean.valueOf(remoteClass.e);
        l lVar3 = this.d;
        lVar3.g(writer, boolValueOf);
        writer.l("membersCanPost");
        Z.q(remoteClass.f, lVar3, writer, "membersCanInvite");
        Z.q(remoteClass.g, lVar3, writer, "creatorId");
        Z.k(remoteClass.h, lVar, writer, DBGroupFields.Names.AUTO_JOIN_LINK);
        this.e.g(writer, remoteClass.i);
        writer.l("_numMembers");
        Z.k(remoteClass.j, lVar, writer, DBFolderFields.Names.NUM_SETS);
        Z.k(remoteClass.k, lVar, writer, "timestamp");
        l lVar4 = this.f;
        lVar4.g(writer, remoteClass.l);
        writer.l("lastModified");
        lVar4.g(writer, remoteClass.m);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(RemoteClass)", "toString(...)");
    }
}
