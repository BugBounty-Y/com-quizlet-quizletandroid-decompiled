package com.quizlet.data.model;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class UserJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public final com.squareup.moshi.l h;
    public volatile Constructor i;

    public UserJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "username", "timestamp", "lastModified", DBUserFields.Names.IS_VERIFIED, "upgradeType", DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, "isLocked", "imageURL", DBUserFields.Names.TIME_ZONE, "profileImageID", "isDeleted", "numCreatedSets", "numClassMemberships", "isUnderAge");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "username");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Boolean.TYPE, m, DBUserFields.Names.IS_VERIFIED);
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Integer.TYPE, m, "upgradeType");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(String.class, m, DBUserFields.Names.TIME_ZONE);
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(Integer.class, m, "numCreatedSets");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        com.squareup.moshi.l lVarA7 = moshi.a(Boolean.class, m, "isUnderAge");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        Long l = null;
        String str = null;
        Long l2 = null;
        Long l3 = null;
        Boolean bool = null;
        Integer num = null;
        Integer num2 = null;
        Boolean bool2 = null;
        String str2 = null;
        Boolean bool3 = null;
        Integer num3 = null;
        String str3 = null;
        String str4 = null;
        Integer num4 = null;
        Boolean bool4 = null;
        while (true) {
            Long l4 = l;
            String str5 = str;
            Long l5 = l2;
            Long l6 = l3;
            Boolean bool5 = bool;
            Integer num5 = num;
            Integer num6 = num2;
            if (!reader.l()) {
                Boolean bool6 = bool2;
                reader.i();
                if (i == -16385) {
                    if (l4 == null) {
                        throw com.squareup.moshi.internal.b.e("id", "id", reader);
                    }
                    long jLongValue = l4.longValue();
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.e("username", "username", reader);
                    }
                    if (l5 == null) {
                        throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                    }
                    long jLongValue2 = l5.longValue();
                    if (l6 == null) {
                        throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                    }
                    long jLongValue3 = l6.longValue();
                    if (bool5 == null) {
                        throw com.squareup.moshi.internal.b.e(DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.IS_VERIFIED, reader);
                    }
                    boolean zBooleanValue = bool5.booleanValue();
                    if (num5 == null) {
                        throw com.squareup.moshi.internal.b.e("upgradeType", "upgradeType", reader);
                    }
                    String str6 = str2;
                    int iIntValue = num5.intValue();
                    if (num6 == null) {
                        throw com.squareup.moshi.internal.b.e(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, reader);
                    }
                    Boolean bool7 = bool3;
                    int iIntValue2 = num6.intValue();
                    if (bool6 == null) {
                        throw com.squareup.moshi.internal.b.e("isLocked", "isLocked", reader);
                    }
                    Integer num7 = num3;
                    boolean zBooleanValue2 = bool6.booleanValue();
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.e("imageURL", "imageURL", reader);
                    }
                    if (bool7 != null) {
                        return new User(jLongValue, str5, jLongValue2, jLongValue3, zBooleanValue, iIntValue, iIntValue2, zBooleanValue2, str3, str4, str6, bool7.booleanValue(), num7, num4, bool4);
                    }
                    throw com.squareup.moshi.internal.b.e("isDeleted", "isDeleted", reader);
                }
                String str7 = str2;
                Boolean bool8 = bool3;
                Constructor declaredConstructor = this.i;
                if (declaredConstructor == null) {
                    Class cls = com.squareup.moshi.internal.b.c;
                    Class cls2 = Long.TYPE;
                    Class cls3 = Boolean.TYPE;
                    Class cls4 = Integer.TYPE;
                    declaredConstructor = User.class.getDeclaredConstructor(cls2, String.class, cls2, cls2, cls3, cls4, cls4, cls3, String.class, String.class, String.class, cls3, Integer.class, Integer.class, Boolean.class, cls4, cls);
                    this.i = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                }
                if (l4 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("username", "username", reader);
                }
                if (l5 == null) {
                    throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                }
                if (l6 == null) {
                    throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                }
                if (bool5 == null) {
                    throw com.squareup.moshi.internal.b.e(DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.IS_VERIFIED, reader);
                }
                if (num5 == null) {
                    throw com.squareup.moshi.internal.b.e("upgradeType", "upgradeType", reader);
                }
                if (num6 == null) {
                    throw com.squareup.moshi.internal.b.e(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, reader);
                }
                if (bool6 == null) {
                    throw com.squareup.moshi.internal.b.e("isLocked", "isLocked", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("imageURL", "imageURL", reader);
                }
                if (bool8 == null) {
                    throw com.squareup.moshi.internal.b.e("isDeleted", "isDeleted", reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(l4, str5, l5, l6, bool5, num5, num6, bool6, str3, str4, str7, bool8, num3, num4, bool4, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (User) objNewInstance;
            }
            Boolean bool9 = bool2;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    bool2 = bool9;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 1:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("username", "username", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 2:
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("timestamp", "timestamp", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 3:
                    l3 = (Long) this.b.a(reader);
                    if (l3 == null) {
                        throw com.squareup.moshi.internal.b.k("lastModified", "lastModified", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 4:
                    bool = (Boolean) this.d.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k(DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.IS_VERIFIED, reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    num = num5;
                    num2 = num6;
                case 5:
                    num = (Integer) this.e.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("upgradeType", "upgradeType", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num2 = num6;
                case 6:
                    num2 = (Integer) this.e.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                case 7:
                    bool2 = (Boolean) this.d.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("isLocked", "isLocked", reader);
                    }
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 8:
                    str3 = (String) this.c.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("imageURL", "imageURL", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 9:
                    str4 = (String) this.f.a(reader);
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 10:
                    str2 = (String) this.f.a(reader);
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 11:
                    bool3 = (Boolean) this.d.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 12:
                    num3 = (Integer) this.g.a(reader);
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 13:
                    num4 = (Integer) this.g.a(reader);
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                case 14:
                    bool4 = (Boolean) this.h.a(reader);
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
                    i = -16385;
                default:
                    bool2 = bool9;
                    l = l4;
                    str = str5;
                    l2 = l5;
                    l3 = l6;
                    bool = bool5;
                    num = num5;
                    num2 = num6;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        User user = (User) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (user == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(user.a);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("username");
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, user.b);
        writer.l("timestamp");
        com.google.android.gms.measurement.internal.Z.k(user.c, lVar, writer, "lastModified");
        com.google.android.gms.measurement.internal.Z.k(user.d, lVar, writer, DBUserFields.Names.IS_VERIFIED);
        Boolean boolValueOf = Boolean.valueOf(user.e);
        com.squareup.moshi.l lVar3 = this.d;
        lVar3.g(writer, boolValueOf);
        writer.l("upgradeType");
        Integer numValueOf = Integer.valueOf(user.f);
        com.squareup.moshi.l lVar4 = this.e;
        lVar4.g(writer, numValueOf);
        writer.l(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE);
        AbstractC4178x.p(user.g, lVar4, writer, "isLocked");
        com.google.android.gms.measurement.internal.Z.q(user.h, lVar3, writer, "imageURL");
        lVar2.g(writer, user.i);
        writer.l(DBUserFields.Names.TIME_ZONE);
        com.squareup.moshi.l lVar5 = this.f;
        lVar5.g(writer, user.j);
        writer.l("profileImageID");
        lVar5.g(writer, user.k);
        writer.l("isDeleted");
        com.google.android.gms.measurement.internal.Z.q(user.l, lVar3, writer, "numCreatedSets");
        com.squareup.moshi.l lVar6 = this.g;
        lVar6.g(writer, user.m);
        writer.l("numClassMemberships");
        lVar6.g(writer, user.n);
        writer.l("isUnderAge");
        this.h.g(writer, user.o);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(26, "GeneratedJsonAdapter(User)", "toString(...)");
    }
}
