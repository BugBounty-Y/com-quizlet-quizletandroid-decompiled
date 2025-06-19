package com.quizlet.data.model;

import com.comscore.streaming.EventType;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudySetJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public final com.squareup.moshi.l h;
    public volatile Constructor i;

    public StudySetJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "timestamp", "lastModified", DBStudySetFields.Names.PUBLISHED_TIMESTAMP, "creatorId", "wordLang", "defLang", "title", "passwordUse", "passwordEdit", DBStudySetFields.Names.ACCESS_TYPE, DBStudySetFields.Names.ACCESS_CODE_PREFIX, OTUXParamsKeys.OT_UX_DESCRIPTION, "numTerms", "hasImages", "parentId", "creationSource", "privacyLockStatus", DBStudySetFields.Names.HAS_DIAGRAMS, "webUrl", "thumbnailUrl", "price", "purchasableType", "localId", "isDeleted", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "isDirty", DBStudySetFields.Names.READY_TO_CREATE, "isEligibleForPracticeTests");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Integer.TYPE, m, "timestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "wordLang");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Boolean.TYPE, m, "passwordUse");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(String.class, m, DBStudySetFields.Names.ACCESS_CODE_PREFIX);
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(Long.class, m, BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        com.squareup.moshi.l lVarA7 = moshi.a(Boolean.class, m, "isEligibleForPracticeTests");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        String str;
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i2 = -1;
        Long l = 0L;
        Boolean bool2 = bool;
        Boolean bool3 = bool2;
        Boolean bool4 = bool3;
        Long l2 = null;
        Integer num = null;
        Integer num2 = null;
        Integer num3 = null;
        Long l3 = null;
        Boolean bool5 = null;
        Boolean bool6 = null;
        Integer num4 = null;
        Integer num5 = null;
        Boolean bool7 = null;
        Integer num6 = null;
        Integer num7 = null;
        Integer num8 = null;
        Boolean bool8 = null;
        Integer num9 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        String str9 = null;
        Long l4 = null;
        Boolean bool9 = null;
        while (true) {
            Long l5 = l2;
            Integer num10 = num;
            Integer num11 = num2;
            Integer num12 = num3;
            Long l6 = l3;
            Boolean bool10 = bool5;
            Boolean bool11 = bool6;
            int i3 = i2;
            if (!reader.l()) {
                reader.i();
                if (i3 == -494927873) {
                    if (l5 == null) {
                        throw com.squareup.moshi.internal.b.e("id", "id", reader);
                    }
                    long jLongValue = l5.longValue();
                    if (num10 == null) {
                        throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                    }
                    int iIntValue = num10.intValue();
                    if (num11 == null) {
                        throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                    }
                    int iIntValue2 = num11.intValue();
                    if (num12 == null) {
                        throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.PUBLISHED_TIMESTAMP, DBStudySetFields.Names.PUBLISHED_TIMESTAMP, reader);
                    }
                    int iIntValue3 = num12.intValue();
                    if (l6 == null) {
                        throw com.squareup.moshi.internal.b.e("creatorId", "creatorId", reader);
                    }
                    long jLongValue2 = l6.longValue();
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.e("wordLang", "wordLang", reader);
                    }
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.e("defLang", "defLang", reader);
                    }
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.e("title", "title", reader);
                    }
                    if (bool10 == null) {
                        throw com.squareup.moshi.internal.b.e("passwordUse", "passwordUse", reader);
                    }
                    boolean zBooleanValue = bool10.booleanValue();
                    if (bool11 == null) {
                        throw com.squareup.moshi.internal.b.e("passwordEdit", "passwordEdit", reader);
                    }
                    boolean zBooleanValue2 = bool11.booleanValue();
                    if (num4 == null) {
                        throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.ACCESS_TYPE, DBStudySetFields.Names.ACCESS_TYPE, reader);
                    }
                    int iIntValue4 = num4.intValue();
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    if (num5 == null) {
                        throw com.squareup.moshi.internal.b.e("numTerms", "numTerms", reader);
                    }
                    int iIntValue5 = num5.intValue();
                    if (bool7 == null) {
                        throw com.squareup.moshi.internal.b.e("hasImages", "hasImages", reader);
                    }
                    boolean zBooleanValue3 = bool7.booleanValue();
                    if (num6 == null) {
                        throw com.squareup.moshi.internal.b.e("parentId", "parentId", reader);
                    }
                    int iIntValue6 = num6.intValue();
                    if (num7 == null) {
                        throw com.squareup.moshi.internal.b.e("creationSource", "creationSource", reader);
                    }
                    int iIntValue7 = num7.intValue();
                    if (num8 == null) {
                        throw com.squareup.moshi.internal.b.e("privacyLockStatus", "privacyLockStatus", reader);
                    }
                    int iIntValue8 = num8.intValue();
                    if (bool8 == null) {
                        throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.HAS_DIAGRAMS, DBStudySetFields.Names.HAS_DIAGRAMS, reader);
                    }
                    boolean zBooleanValue4 = bool8.booleanValue();
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.e("webUrl", "webUrl", reader);
                    }
                    if (num9 != null) {
                        return new StudySet(jLongValue, iIntValue, iIntValue2, iIntValue3, jLongValue2, str2, str3, str4, zBooleanValue, zBooleanValue2, iIntValue4, str5, str6, iIntValue5, zBooleanValue3, iIntValue6, iIntValue7, iIntValue8, zBooleanValue4, str7, str8, str9, num9.intValue(), l.longValue(), bool2.booleanValue(), l4, bool3.booleanValue(), bool4.booleanValue(), bool9);
                    }
                    throw com.squareup.moshi.internal.b.e("purchasableType", "purchasableType", reader);
                }
                Constructor declaredConstructor = this.i;
                if (declaredConstructor == null) {
                    Class cls = com.squareup.moshi.internal.b.c;
                    Class cls2 = Long.TYPE;
                    Class cls3 = Integer.TYPE;
                    Class cls4 = Boolean.TYPE;
                    str = "title";
                    declaredConstructor = StudySet.class.getDeclaredConstructor(cls2, cls3, cls3, cls3, cls2, String.class, String.class, String.class, cls4, cls4, cls3, String.class, String.class, cls3, cls4, cls3, cls3, cls3, cls4, String.class, String.class, String.class, cls3, cls2, cls4, Long.class, cls4, cls4, Boolean.class, cls3, cls);
                    this.i = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    str = "title";
                }
                if (l5 == null) {
                    throw com.squareup.moshi.internal.b.e("id", "id", reader);
                }
                if (num10 == null) {
                    throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
                }
                if (num11 == null) {
                    throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
                }
                if (num12 == null) {
                    throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.PUBLISHED_TIMESTAMP, DBStudySetFields.Names.PUBLISHED_TIMESTAMP, reader);
                }
                if (l6 == null) {
                    throw com.squareup.moshi.internal.b.e("creatorId", "creatorId", reader);
                }
                if (str2 == null) {
                    throw com.squareup.moshi.internal.b.e("wordLang", "wordLang", reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("defLang", "defLang", reader);
                }
                if (str4 == null) {
                    String str10 = str;
                    throw com.squareup.moshi.internal.b.e(str10, str10, reader);
                }
                if (bool10 == null) {
                    throw com.squareup.moshi.internal.b.e("passwordUse", "passwordUse", reader);
                }
                if (bool11 == null) {
                    throw com.squareup.moshi.internal.b.e("passwordEdit", "passwordEdit", reader);
                }
                if (num4 == null) {
                    throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.ACCESS_TYPE, DBStudySetFields.Names.ACCESS_TYPE, reader);
                }
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (num5 == null) {
                    throw com.squareup.moshi.internal.b.e("numTerms", "numTerms", reader);
                }
                if (bool7 == null) {
                    throw com.squareup.moshi.internal.b.e("hasImages", "hasImages", reader);
                }
                if (num6 == null) {
                    throw com.squareup.moshi.internal.b.e("parentId", "parentId", reader);
                }
                if (num7 == null) {
                    throw com.squareup.moshi.internal.b.e("creationSource", "creationSource", reader);
                }
                if (num8 == null) {
                    throw com.squareup.moshi.internal.b.e("privacyLockStatus", "privacyLockStatus", reader);
                }
                if (bool8 == null) {
                    throw com.squareup.moshi.internal.b.e(DBStudySetFields.Names.HAS_DIAGRAMS, DBStudySetFields.Names.HAS_DIAGRAMS, reader);
                }
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("webUrl", "webUrl", reader);
                }
                if (num9 == null) {
                    throw com.squareup.moshi.internal.b.e("purchasableType", "purchasableType", reader);
                }
                Object objNewInstance = declaredConstructor.newInstance(l5, num10, num11, num12, l6, str2, str3, str4, bool10, bool11, num4, str5, str6, num5, bool7, num6, num7, num8, bool8, str7, str8, str9, num9, l, bool2, l4, bool3, bool4, bool9, Integer.valueOf(i3), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (StudySet) objNewInstance;
            }
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 0:
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 1:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("timestamp", "timestamp", reader);
                    }
                    l2 = l5;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 2:
                    num2 = (Integer) this.c.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("lastModified", "lastModified", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 3:
                    num3 = (Integer) this.c.a(reader);
                    if (num3 == null) {
                        throw com.squareup.moshi.internal.b.k(DBStudySetFields.Names.PUBLISHED_TIMESTAMP, DBStudySetFields.Names.PUBLISHED_TIMESTAMP, reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 4:
                    l3 = (Long) this.b.a(reader);
                    if (l3 == null) {
                        throw com.squareup.moshi.internal.b.k("creatorId", "creatorId", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 5:
                    str2 = (String) this.d.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("wordLang", "wordLang", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 6:
                    str3 = (String) this.d.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("defLang", "defLang", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 7:
                    str4 = (String) this.d.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("title", "title", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 8:
                    bool5 = (Boolean) this.e.a(reader);
                    if (bool5 == null) {
                        throw com.squareup.moshi.internal.b.k("passwordUse", "passwordUse", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool6 = bool11;
                    i2 = i3;
                case 9:
                    bool6 = (Boolean) this.e.a(reader);
                    if (bool6 == null) {
                        throw com.squareup.moshi.internal.b.k("passwordEdit", "passwordEdit", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    i2 = i3;
                case 10:
                    num4 = (Integer) this.c.a(reader);
                    if (num4 == null) {
                        throw com.squareup.moshi.internal.b.k(DBStudySetFields.Names.ACCESS_TYPE, DBStudySetFields.Names.ACCESS_TYPE, reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 11:
                    str5 = (String) this.f.a(reader);
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 12:
                    str6 = (String) this.d.a(reader);
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 13:
                    num5 = (Integer) this.c.a(reader);
                    if (num5 == null) {
                        throw com.squareup.moshi.internal.b.k("numTerms", "numTerms", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 14:
                    bool7 = (Boolean) this.e.a(reader);
                    if (bool7 == null) {
                        throw com.squareup.moshi.internal.b.k("hasImages", "hasImages", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 15:
                    num6 = (Integer) this.c.a(reader);
                    if (num6 == null) {
                        throw com.squareup.moshi.internal.b.k("parentId", "parentId", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 16:
                    num7 = (Integer) this.c.a(reader);
                    if (num7 == null) {
                        throw com.squareup.moshi.internal.b.k("creationSource", "creationSource", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 17:
                    num8 = (Integer) this.c.a(reader);
                    if (num8 == null) {
                        throw com.squareup.moshi.internal.b.k("privacyLockStatus", "privacyLockStatus", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 18:
                    bool8 = (Boolean) this.e.a(reader);
                    if (bool8 == null) {
                        throw com.squareup.moshi.internal.b.k(DBStudySetFields.Names.HAS_DIAGRAMS, DBStudySetFields.Names.HAS_DIAGRAMS, reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 19:
                    str7 = (String) this.d.a(reader);
                    if (str7 == null) {
                        throw com.squareup.moshi.internal.b.k("webUrl", "webUrl", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 20:
                    str8 = (String) this.f.a(reader);
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case 21:
                    str9 = (String) this.f.a(reader);
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case EventType.WINDOW_STATE /* 22 */:
                    num9 = (Integer) this.c.a(reader);
                    if (num9 == null) {
                        throw com.squareup.moshi.internal.b.k("purchasableType", "purchasableType", reader);
                    }
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case EventType.AUDIO /* 23 */:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("localId", "localId", reader);
                    }
                    i = -8388609;
                    i2 = i3 & i;
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                case EventType.VIDEO /* 24 */:
                    bool2 = (Boolean) this.e.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    i = -16777217;
                    i2 = i3 & i;
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                case EventType.SUBS /* 25 */:
                    l4 = (Long) this.g.a(reader);
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
                case EventType.CDN /* 26 */:
                    bool3 = (Boolean) this.e.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("isDirty", "isDirty", reader);
                    }
                    i = -67108865;
                    i2 = i3 & i;
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                case 27:
                    bool4 = (Boolean) this.e.a(reader);
                    if (bool4 == null) {
                        throw com.squareup.moshi.internal.b.k(DBStudySetFields.Names.READY_TO_CREATE, DBStudySetFields.Names.READY_TO_CREATE, reader);
                    }
                    i = -134217729;
                    i2 = i3 & i;
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                case 28:
                    bool9 = (Boolean) this.h.a(reader);
                    i = -268435457;
                    i2 = i3 & i;
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                default:
                    l2 = l5;
                    num = num10;
                    num2 = num11;
                    num3 = num12;
                    l3 = l6;
                    bool5 = bool10;
                    bool6 = bool11;
                    i2 = i3;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        StudySet studySet = (StudySet) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studySet == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(studySet.a);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("timestamp");
        Integer numValueOf = Integer.valueOf(studySet.b);
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, numValueOf);
        writer.l("lastModified");
        AbstractC4178x.p(studySet.c, lVar2, writer, DBStudySetFields.Names.PUBLISHED_TIMESTAMP);
        AbstractC4178x.p(studySet.d, lVar2, writer, "creatorId");
        com.google.android.gms.measurement.internal.Z.k(studySet.e, lVar, writer, "wordLang");
        com.squareup.moshi.l lVar3 = this.d;
        lVar3.g(writer, studySet.f);
        writer.l("defLang");
        lVar3.g(writer, studySet.g);
        writer.l("title");
        lVar3.g(writer, studySet.h);
        writer.l("passwordUse");
        Boolean boolValueOf = Boolean.valueOf(studySet.i);
        com.squareup.moshi.l lVar4 = this.e;
        lVar4.g(writer, boolValueOf);
        writer.l("passwordEdit");
        com.google.android.gms.measurement.internal.Z.q(studySet.j, lVar4, writer, DBStudySetFields.Names.ACCESS_TYPE);
        AbstractC4178x.p(studySet.k, lVar2, writer, DBStudySetFields.Names.ACCESS_CODE_PREFIX);
        com.squareup.moshi.l lVar5 = this.f;
        lVar5.g(writer, studySet.l);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar3.g(writer, studySet.m);
        writer.l("numTerms");
        AbstractC4178x.p(studySet.n, lVar2, writer, "hasImages");
        com.google.android.gms.measurement.internal.Z.q(studySet.o, lVar4, writer, "parentId");
        AbstractC4178x.p(studySet.p, lVar2, writer, "creationSource");
        AbstractC4178x.p(studySet.q, lVar2, writer, "privacyLockStatus");
        AbstractC4178x.p(studySet.r, lVar2, writer, DBStudySetFields.Names.HAS_DIAGRAMS);
        com.google.android.gms.measurement.internal.Z.q(studySet.s, lVar4, writer, "webUrl");
        lVar3.g(writer, studySet.t);
        writer.l("thumbnailUrl");
        lVar5.g(writer, studySet.u);
        writer.l("price");
        lVar5.g(writer, studySet.v);
        writer.l("purchasableType");
        AbstractC4178x.p(studySet.w, lVar2, writer, "localId");
        com.google.android.gms.measurement.internal.Z.k(studySet.x, lVar, writer, "isDeleted");
        com.google.android.gms.measurement.internal.Z.q(studySet.y, lVar4, writer, BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        this.g.g(writer, studySet.z);
        writer.l("isDirty");
        com.google.android.gms.measurement.internal.Z.q(studySet.A, lVar4, writer, DBStudySetFields.Names.READY_TO_CREATE);
        com.google.android.gms.measurement.internal.Z.q(studySet.B, lVar4, writer, "isEligibleForPracticeTests");
        this.h.g(writer, studySet.C);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(StudySet)", "toString(...)");
    }
}
