package com.quizlet.remote.model.set;

import com.comscore.streaming.EventType;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.squareup.moshi.D;
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
public final class RemoteSetJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public volatile Constructor h;

    public RemoteSetJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "timestamp", "lastModified", DBStudySetFields.Names.PUBLISHED_TIMESTAMP, "creatorId", "wordLang", "defLang", "title", "passwordUse", "passwordEdit", DBStudySetFields.Names.ACCESS_TYPE, DBStudySetFields.Names.ACCESS_CODE_PREFIX, OTUXParamsKeys.OT_UX_DESCRIPTION, "numTerms", "hasImages", "parentId", "creationSource", "privacyLockStatus", DBStudySetFields.Names.HAS_DIAGRAMS, "_webUrl", DBStudySetFields.Names.THUMBNAIL_URL, "price", "purchasableType", "clientId", "isDeleted", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "isDirty", "isEligibleForPracticeTests");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, "timestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "creatorId");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "wordLang");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Boolean.class, m, "passwordUse");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i2 = -1;
        Boolean bool2 = bool;
        Boolean bool3 = bool2;
        Long l = null;
        Boolean bool4 = null;
        Integer num = null;
        String str = null;
        Long l2 = null;
        Boolean bool5 = null;
        Integer num2 = null;
        Integer num3 = null;
        Integer num4 = null;
        Long l3 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Boolean bool6 = null;
        String str5 = null;
        Integer num5 = null;
        Boolean bool7 = null;
        Integer num6 = null;
        Integer num7 = null;
        Integer num8 = null;
        Boolean bool8 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        Integer num9 = null;
        Long l4 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    continue;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    continue;
                case 1:
                    num2 = (Integer) this.c.a(reader);
                    continue;
                case 2:
                    num3 = (Integer) this.c.a(reader);
                    continue;
                case 3:
                    num4 = (Integer) this.c.a(reader);
                    continue;
                case 4:
                    l3 = (Long) this.d.a(reader);
                    continue;
                case 5:
                    str2 = (String) this.e.a(reader);
                    continue;
                case 6:
                    str3 = (String) this.e.a(reader);
                    continue;
                case 7:
                    str4 = (String) this.e.a(reader);
                    continue;
                case 8:
                    bool6 = (Boolean) this.f.a(reader);
                    continue;
                case 9:
                    bool4 = (Boolean) this.f.a(reader);
                    continue;
                case 10:
                    num = (Integer) this.c.a(reader);
                    continue;
                case 11:
                    str = (String) this.e.a(reader);
                    continue;
                case 12:
                    str5 = (String) this.e.a(reader);
                    continue;
                case 13:
                    num5 = (Integer) this.c.a(reader);
                    continue;
                case 14:
                    bool7 = (Boolean) this.f.a(reader);
                    continue;
                case 15:
                    num6 = (Integer) this.c.a(reader);
                    continue;
                case 16:
                    num7 = (Integer) this.c.a(reader);
                    continue;
                case 17:
                    num8 = (Integer) this.c.a(reader);
                    continue;
                case 18:
                    bool8 = (Boolean) this.f.a(reader);
                    continue;
                case 19:
                    str6 = (String) this.e.a(reader);
                    continue;
                case 20:
                    str7 = (String) this.e.a(reader);
                    continue;
                case 21:
                    str8 = (String) this.e.a(reader);
                    continue;
                case EventType.WINDOW_STATE /* 22 */:
                    num9 = (Integer) this.c.a(reader);
                    continue;
                case EventType.AUDIO /* 23 */:
                    l4 = (Long) this.d.a(reader);
                    continue;
                case EventType.VIDEO /* 24 */:
                    bool2 = (Boolean) this.g.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    i = -16777217;
                    break;
                case EventType.SUBS /* 25 */:
                    l2 = (Long) this.d.a(reader);
                    continue;
                case EventType.CDN /* 26 */:
                    bool3 = (Boolean) this.g.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("isDirty", "isDirty", reader);
                    }
                    i = -67108865;
                    break;
                case 27:
                    bool5 = (Boolean) this.f.a(reader);
                    i = -134217729;
                    break;
            }
            i2 &= i;
        }
        reader.i();
        if (i2 == -218103809) {
            Boolean bool9 = bool5;
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("id", "id", reader);
            }
            return new RemoteSet(l.longValue(), num2, num3, num4, l3, str2, str3, str4, bool6, bool4, num, str, str5, num5, bool7, num6, num7, num8, bool8, str6, str7, str8, num9, l4, bool2.booleanValue(), l2, bool3.booleanValue(), bool9);
        }
        Boolean bool10 = bool5;
        Constructor declaredConstructor = this.h;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Long.TYPE;
            Class cls3 = Boolean.TYPE;
            declaredConstructor = RemoteSet.class.getDeclaredConstructor(cls2, Integer.class, Integer.class, Integer.class, Long.class, String.class, String.class, String.class, Boolean.class, Boolean.class, Integer.class, String.class, String.class, Integer.class, Boolean.class, Integer.class, Integer.class, Integer.class, Boolean.class, String.class, String.class, String.class, Integer.class, Long.class, cls3, Long.class, cls3, Boolean.class, Integer.TYPE, cls);
            this.h = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, num2, num3, num4, l3, str2, str3, str4, bool6, bool4, num, str, str5, num5, bool7, num6, num7, num8, bool8, str6, str7, str8, num9, l4, bool2, l2, bool3, bool10, Integer.valueOf(i2), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteSet) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSet remoteSet = (RemoteSet) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSet == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteSet.a));
        writer.l("timestamp");
        l lVar = this.c;
        lVar.g(writer, remoteSet.b);
        writer.l("lastModified");
        lVar.g(writer, remoteSet.c);
        writer.l(DBStudySetFields.Names.PUBLISHED_TIMESTAMP);
        lVar.g(writer, remoteSet.d);
        writer.l("creatorId");
        l lVar2 = this.d;
        lVar2.g(writer, remoteSet.e);
        writer.l("wordLang");
        l lVar3 = this.e;
        lVar3.g(writer, remoteSet.f);
        writer.l("defLang");
        lVar3.g(writer, remoteSet.g);
        writer.l("title");
        lVar3.g(writer, remoteSet.h);
        writer.l("passwordUse");
        l lVar4 = this.f;
        lVar4.g(writer, remoteSet.i);
        writer.l("passwordEdit");
        lVar4.g(writer, remoteSet.j);
        writer.l(DBStudySetFields.Names.ACCESS_TYPE);
        lVar.g(writer, remoteSet.k);
        writer.l(DBStudySetFields.Names.ACCESS_CODE_PREFIX);
        lVar3.g(writer, remoteSet.l);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar3.g(writer, remoteSet.m);
        writer.l("numTerms");
        lVar.g(writer, remoteSet.n);
        writer.l("hasImages");
        lVar4.g(writer, remoteSet.o);
        writer.l("parentId");
        lVar.g(writer, remoteSet.p);
        writer.l("creationSource");
        lVar.g(writer, remoteSet.q);
        writer.l("privacyLockStatus");
        lVar.g(writer, remoteSet.r);
        writer.l(DBStudySetFields.Names.HAS_DIAGRAMS);
        lVar4.g(writer, remoteSet.s);
        writer.l("_webUrl");
        lVar3.g(writer, remoteSet.t);
        writer.l(DBStudySetFields.Names.THUMBNAIL_URL);
        lVar3.g(writer, remoteSet.u);
        writer.l("price");
        lVar3.g(writer, remoteSet.v);
        writer.l("purchasableType");
        lVar.g(writer, remoteSet.w);
        writer.l("clientId");
        lVar2.g(writer, remoteSet.x);
        writer.l("isDeleted");
        Boolean boolValueOf = Boolean.valueOf(remoteSet.y);
        l lVar5 = this.g;
        lVar5.g(writer, boolValueOf);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        lVar2.g(writer, remoteSet.z);
        writer.l("isDirty");
        Z.q(remoteSet.A, lVar5, writer, "isEligibleForPracticeTests");
        lVar4.g(writer, remoteSet.B);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(31, "GeneratedJsonAdapter(RemoteSet)", "toString(...)");
    }
}
