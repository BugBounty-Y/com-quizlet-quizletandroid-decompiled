package com.quizlet.data.model;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ContentFolderJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public volatile Constructor h;

    public ContentFolderJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "isDeleted", "lastModified", "localId", "isDirty", "personId", "name", OTUXParamsKeys.OT_UX_DESCRIPTION, "timestamp", "isHidden", "webUrl", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "numStudySets", "numStudyMaterials", "folderTypeLabel");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(String.class, m, "webUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(Long.class, m, BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(Integer.class, m, "numStudySets");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        int i = -1;
        Long l = null;
        Boolean bool = null;
        Long l2 = null;
        Long l3 = null;
        Boolean bool2 = null;
        Long l4 = null;
        Long l5 = null;
        Boolean bool3 = null;
        String str2 = null;
        Long l6 = null;
        Integer num = null;
        Integer num2 = null;
        String str3 = null;
        String str4 = null;
        while (true) {
            Long l7 = l;
            Boolean bool4 = bool;
            Long l8 = l2;
            Long l9 = l3;
            Boolean bool5 = bool2;
            Long l10 = l4;
            Long l11 = l5;
            Boolean bool6 = bool3;
            if (!reader.l()) {
                String str5 = str2;
                reader.i();
                if (i == -28673) {
                    if (l7 == null) {
                        throw com.squareup.moshi.internal.b.e("id", "id", reader);
                    }
                    long jLongValue = l7.longValue();
                    if (bool4 == null) {
                        throw com.squareup.moshi.internal.b.e("isDeleted", "isDeleted", reader);
                    }
                    boolean zBooleanValue = bool4.booleanValue();
                    if (l8 == null) {
                        throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                    }
                    Long l12 = l6;
                    long jLongValue2 = l8.longValue();
                    if (l9 == null) {
                        throw com.squareup.moshi.internal.b.e("localId", "localId", reader);
                    }
                    Integer num3 = num;
                    Integer num4 = num2;
                    long jLongValue3 = l9.longValue();
                    if (bool5 == null) {
                        throw com.squareup.moshi.internal.b.e("isDirty", "isDirty", reader);
                    }
                    boolean zBooleanValue2 = bool5.booleanValue();
                    if (l10 == null) {
                        throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
                    }
                    long jLongValue4 = l10.longValue();
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.e("name", "name", reader);
                    }
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    if (l11 == null) {
                        throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                    }
                    long jLongValue5 = l11.longValue();
                    if (bool6 == null) {
                        throw com.squareup.moshi.internal.b.e("isHidden", "isHidden", reader);
                    }
                    boolean zBooleanValue3 = bool6.booleanValue();
                    Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
                    return new ContentFolder(jLongValue, zBooleanValue, jLongValue2, jLongValue3, zBooleanValue2, jLongValue4, str3, str4, jLongValue5, zBooleanValue3, str5, l12, num3, num4, str);
                }
                String str6 = str;
                Integer num5 = num2;
                Long l13 = l6;
                Integer num6 = num;
                Constructor declaredConstructor = this.h;
                if (declaredConstructor == null) {
                    Class cls = com.squareup.moshi.internal.b.c;
                    Class cls2 = Long.TYPE;
                    Class cls3 = Boolean.TYPE;
                    declaredConstructor = ContentFolder.class.getDeclaredConstructor(cls2, cls3, cls2, cls2, cls3, cls2, String.class, String.class, cls2, cls3, String.class, Long.class, Integer.class, Integer.class, String.class, Integer.TYPE, cls);
                    this.h = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                }
                if (l7 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                if (bool4 == null) {
                    throw com.squareup.moshi.internal.b.e("isDeleted", "isDeleted", reader);
                }
                if (l8 == null) {
                    throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                }
                if (l9 == null) {
                    throw com.squareup.moshi.internal.b.e("localId", "localId", reader);
                }
                if (bool5 == null) {
                    throw com.squareup.moshi.internal.b.e("isDirty", "isDirty", reader);
                }
                if (l10 == null) {
                    throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (l11 == null) {
                    throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                }
                if (bool6 == null) {
                    throw com.squareup.moshi.internal.b.e("isHidden", "isHidden", reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(l7, bool4, l8, l9, bool5, l10, str3, str4, l11, bool6, str5, l13, num6, num5, str6, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (ContentFolder) objNewInstance;
            }
            String str7 = str2;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 1:
                    bool = (Boolean) this.c.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    l = l7;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 2:
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("lastModified", "lastModified", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 3:
                    l3 = (Long) this.b.a(reader);
                    if (l3 == null) {
                        throw com.squareup.moshi.internal.b.k("localId", "localId", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 4:
                    bool2 = (Boolean) this.c.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("isDirty", "isDirty", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 5:
                    l4 = (Long) this.b.a(reader);
                    if (l4 == null) {
                        throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 6:
                    str3 = (String) this.d.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 7:
                    str4 = (String) this.d.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 8:
                    Long l14 = (Long) this.b.a(reader);
                    if (l14 == null) {
                        throw com.squareup.moshi.internal.b.k("timestamp", "timestamp", reader);
                    }
                    l5 = l14;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    bool3 = bool6;
                case 9:
                    Boolean bool7 = (Boolean) this.c.a(reader);
                    if (bool7 == null) {
                        throw com.squareup.moshi.internal.b.k("isHidden", "isHidden", reader);
                    }
                    bool3 = bool7;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                case 10:
                    str2 = (String) this.e.a(reader);
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                case 11:
                    l6 = (Long) this.f.a(reader);
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 12:
                    num = (Integer) this.g.a(reader);
                    i &= -4097;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 13:
                    num2 = (Integer) this.g.a(reader);
                    i &= -8193;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                case 14:
                    str = (String) this.d.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("folderTypeLabel", "folderTypeLabel", reader);
                    }
                    i &= -16385;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
                default:
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    str2 = str7;
                    l5 = l11;
                    bool3 = bool6;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        ContentFolder contentFolder = (ContentFolder) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (contentFolder == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(contentFolder.l);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("isDeleted");
        Boolean boolValueOf = Boolean.valueOf(contentFolder.m);
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, boolValueOf);
        writer.l("lastModified");
        com.google.android.gms.measurement.internal.Z.k(contentFolder.n, lVar, writer, "localId");
        com.google.android.gms.measurement.internal.Z.k(contentFolder.o, lVar, writer, "isDirty");
        com.google.android.gms.measurement.internal.Z.q(contentFolder.p, lVar2, writer, "personId");
        com.google.android.gms.measurement.internal.Z.k(contentFolder.q, lVar, writer, "name");
        com.squareup.moshi.l lVar3 = this.d;
        lVar3.g(writer, contentFolder.r);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar3.g(writer, contentFolder.s);
        writer.l("timestamp");
        com.google.android.gms.measurement.internal.Z.k(contentFolder.t, lVar, writer, "isHidden");
        com.google.android.gms.measurement.internal.Z.q(contentFolder.u, lVar2, writer, "webUrl");
        this.e.g(writer, contentFolder.v);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        this.f.g(writer, contentFolder.w);
        writer.l("numStudySets");
        com.squareup.moshi.l lVar4 = this.g;
        lVar4.g(writer, contentFolder.x);
        writer.l("numStudyMaterials");
        lVar4.g(writer, contentFolder.y);
        writer.l("folderTypeLabel");
        lVar3.g(writer, contentFolder.z);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(35, "GeneratedJsonAdapter(ContentFolder)", "toString(...)");
    }
}
