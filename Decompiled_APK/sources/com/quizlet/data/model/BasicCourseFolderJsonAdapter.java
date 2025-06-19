package com.quizlet.data.model;

import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class BasicCourseFolderJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public volatile Constructor h;

    public BasicCourseFolderJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "isDeleted", "lastModified", "localId", "isDirty", "personId", "timestamp", "name", "isHidden", "webUrl", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "schoolCourseDescription", "folderTypeLabel", DBFolderFields.Names.QPF_GENERATION_METHOD);
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
        com.squareup.moshi.l lVarA6 = moshi.a(com.quizlet.generated.enums.M0.class, m, DBFolderFields.Names.QPF_GENERATION_METHOD);
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Long l = null;
        Boolean bool = null;
        Long l2 = null;
        Long l3 = null;
        Boolean bool2 = null;
        Long l4 = null;
        Long l5 = null;
        Boolean bool3 = null;
        Long l6 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        int i = -1;
        com.quizlet.generated.enums.M0 m0 = null;
        while (true) {
            Long l7 = l;
            Boolean bool4 = bool;
            Long l8 = l2;
            Long l9 = l3;
            Boolean bool5 = bool2;
            Long l10 = l4;
            Long l11 = l5;
            Boolean bool6 = bool3;
            Long l12 = l6;
            if (!reader.l()) {
                String str5 = str2;
                reader.i();
                if (i == -12289) {
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
                    long jLongValue2 = l8.longValue();
                    if (l9 == null) {
                        throw com.squareup.moshi.internal.b.e("localId", "localId", reader);
                    }
                    long jLongValue3 = l9.longValue();
                    if (bool5 == null) {
                        throw com.squareup.moshi.internal.b.e("isDirty", "isDirty", reader);
                    }
                    boolean zBooleanValue2 = bool5.booleanValue();
                    if (l10 == null) {
                        throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
                    }
                    long jLongValue4 = l10.longValue();
                    if (l11 == null) {
                        throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                    }
                    long jLongValue5 = l11.longValue();
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.e("name", "name", reader);
                    }
                    if (bool6 == null) {
                        throw com.squareup.moshi.internal.b.e("isHidden", "isHidden", reader);
                    }
                    boolean zBooleanValue3 = bool6.booleanValue();
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.e("schoolCourseDescription", "schoolCourseDescription", reader);
                    }
                    Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
                    Intrinsics.e(m0, "null cannot be cast to non-null type com.quizlet.generated.enums.QPFGenerationMethod");
                    return new BasicCourseFolder(jLongValue, zBooleanValue, jLongValue2, jLongValue3, zBooleanValue2, jLongValue4, jLongValue5, str3, zBooleanValue3, str4, l12, str5, str, m0);
                }
                String str6 = str;
                com.quizlet.generated.enums.M0 m02 = m0;
                Constructor declaredConstructor = this.h;
                if (declaredConstructor == null) {
                    Class cls = com.squareup.moshi.internal.b.c;
                    Class cls2 = Long.TYPE;
                    Class cls3 = Boolean.TYPE;
                    declaredConstructor = BasicCourseFolder.class.getDeclaredConstructor(cls2, cls3, cls2, cls2, cls3, cls2, cls2, String.class, cls3, String.class, Long.class, String.class, String.class, com.quizlet.generated.enums.M0.class, Integer.TYPE, cls);
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
                if (l11 == null) {
                    throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (bool6 == null) {
                    throw com.squareup.moshi.internal.b.e("isHidden", "isHidden", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("schoolCourseDescription", "schoolCourseDescription", reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(l7, bool4, l8, l9, bool5, l10, l11, str3, bool6, str4, l12, str5, str6, m02, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (BasicCourseFolder) objNewInstance;
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
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 0:
                    Long l13 = (Long) this.b.a(reader);
                    if (l13 == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    l = l13;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 1:
                    Boolean bool7 = (Boolean) this.c.a(reader);
                    if (bool7 == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    bool = bool7;
                    l = l7;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 2:
                    Long l14 = (Long) this.b.a(reader);
                    if (l14 == null) {
                        throw com.squareup.moshi.internal.b.k("lastModified", "lastModified", reader);
                    }
                    l2 = l14;
                    l = l7;
                    bool = bool4;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 3:
                    Long l15 = (Long) this.b.a(reader);
                    if (l15 == null) {
                        throw com.squareup.moshi.internal.b.k("localId", "localId", reader);
                    }
                    l3 = l15;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 4:
                    Boolean bool8 = (Boolean) this.c.a(reader);
                    if (bool8 == null) {
                        throw com.squareup.moshi.internal.b.k("isDirty", "isDirty", reader);
                    }
                    bool2 = bool8;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 5:
                    Long l16 = (Long) this.b.a(reader);
                    if (l16 == null) {
                        throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                    }
                    l4 = l16;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 6:
                    Long l17 = (Long) this.b.a(reader);
                    if (l17 == null) {
                        throw com.squareup.moshi.internal.b.k("timestamp", "timestamp", reader);
                    }
                    l5 = l17;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 7:
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
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 8:
                    bool3 = (Boolean) this.c.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("isHidden", "isHidden", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    l6 = l12;
                    str2 = str7;
                case 9:
                    str4 = (String) this.e.a(reader);
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 10:
                    l6 = (Long) this.f.a(reader);
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    str2 = str7;
                case 11:
                    str2 = (String) this.d.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("schoolCourseDescription", "schoolCourseDescription", reader);
                    }
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                case 12:
                    str = (String) this.d.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("folderTypeLabel", "folderTypeLabel", reader);
                    }
                    i &= -4097;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                case 13:
                    m0 = (com.quizlet.generated.enums.M0) this.g.a(reader);
                    if (m0 == null) {
                        throw com.squareup.moshi.internal.b.k(DBFolderFields.Names.QPF_GENERATION_METHOD, DBFolderFields.Names.QPF_GENERATION_METHOD, reader);
                    }
                    i &= -8193;
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
                default:
                    l = l7;
                    bool = bool4;
                    l2 = l8;
                    l3 = l9;
                    bool2 = bool5;
                    l4 = l10;
                    l5 = l11;
                    bool3 = bool6;
                    l6 = l12;
                    str2 = str7;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        BasicCourseFolder basicCourseFolder = (BasicCourseFolder) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (basicCourseFolder == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(basicCourseFolder.m);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("isDeleted");
        Boolean boolValueOf = Boolean.valueOf(basicCourseFolder.n);
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, boolValueOf);
        writer.l("lastModified");
        com.google.android.gms.measurement.internal.Z.k(basicCourseFolder.o, lVar, writer, "localId");
        com.google.android.gms.measurement.internal.Z.k(basicCourseFolder.p, lVar, writer, "isDirty");
        com.google.android.gms.measurement.internal.Z.q(basicCourseFolder.q, lVar2, writer, "personId");
        com.google.android.gms.measurement.internal.Z.k(basicCourseFolder.r, lVar, writer, "timestamp");
        com.google.android.gms.measurement.internal.Z.k(basicCourseFolder.s, lVar, writer, "name");
        com.squareup.moshi.l lVar3 = this.d;
        lVar3.g(writer, basicCourseFolder.t);
        writer.l("isHidden");
        com.google.android.gms.measurement.internal.Z.q(basicCourseFolder.u, lVar2, writer, "webUrl");
        this.e.g(writer, basicCourseFolder.v);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        this.f.g(writer, basicCourseFolder.w);
        writer.l("schoolCourseDescription");
        lVar3.g(writer, basicCourseFolder.x);
        writer.l("folderTypeLabel");
        lVar3.g(writer, basicCourseFolder.y);
        writer.l(DBFolderFields.Names.QPF_GENERATION_METHOD);
        this.g.g(writer, basicCourseFolder.z);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(BasicCourseFolder)", "toString(...)");
    }
}
