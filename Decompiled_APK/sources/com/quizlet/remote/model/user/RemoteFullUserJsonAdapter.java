package com.quizlet.remote.model.user;

import com.airbnb.lottie.parser.moshi.c;
import com.comscore.streaming.EventType;
import com.quizlet.data.model.AbstractC4178x;
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
public final class RemoteFullUserJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RemoteFullUserJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "username", "timestamp", "lastModified", DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.IS_ADMIN, "isLocked", "_imageUrl", DBUserFields.Names.TIME_ZONE, "birthYear", "birthMonth", "birthDay", "isConfirmed", DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, DBUserFields.Names.PROFILE_IMAGE_ID, "email", "_hasPassword", "_hasFacebook", "_hasGoogle", "_isConfirmationRequired", "_canChangeUsername", "_isUnderAge", "_isUnderAgeForAds", "_needsChildDirectedTreatment", "mobileLocale", "userLocalePreference", DBUserFields.Names.NOTIFICATION_TIME, DBUserFields.Names.NOTIFICATIONS_ENABLED, "_isEligibleForFreeTrial", "_hasOptedIntoFreeOfflinePromo", DBUserFields.Names.IS_SELF_LEARNER, DBUserFields.Names.SIGNUP_COUNTRY_CODE, DBUserFields.Names.COUNTRY_CODE);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "username");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "timestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Integer.class, m, "upgradeType");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Boolean.class, m, DBUserFields.Names.IS_VERIFIED);
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        Long l2 = null;
        Long l3 = null;
        Integer num = null;
        Boolean bool = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        String str2 = null;
        String str3 = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Boolean bool4 = null;
        Integer num2 = null;
        String str4 = null;
        String str5 = null;
        Boolean bool5 = null;
        Boolean bool6 = null;
        Boolean bool7 = null;
        Boolean bool8 = null;
        Boolean bool9 = null;
        Boolean bool10 = null;
        Boolean bool11 = null;
        Boolean bool12 = null;
        String str6 = null;
        String str7 = null;
        Long l7 = null;
        Boolean bool13 = null;
        Boolean bool14 = null;
        Boolean bool15 = null;
        Boolean bool16 = null;
        String str8 = null;
        String str9 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.e;
            Long l8 = l;
            l lVar2 = this.d;
            l lVar3 = this.c;
            String str10 = str;
            l lVar4 = this.f;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l8;
                    str = str10;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw b.k("id", "id", reader);
                    }
                    str = str10;
                case 1:
                    str = (String) lVar3.a(reader);
                    l = l8;
                case 2:
                    l2 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 3:
                    l3 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 4:
                    num = (Integer) lVar.a(reader);
                    l = l8;
                    str = str10;
                case 5:
                    bool = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 6:
                    bool2 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 7:
                    bool3 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 8:
                    str2 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 9:
                    str3 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 10:
                    l4 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 11:
                    l5 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 12:
                    l6 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 13:
                    bool4 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 14:
                    num2 = (Integer) lVar.a(reader);
                    l = l8;
                    str = str10;
                case 15:
                    str4 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 16:
                    str5 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 17:
                    bool5 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 18:
                    bool6 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 19:
                    bool7 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 20:
                    bool8 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 21:
                    bool9 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case EventType.WINDOW_STATE /* 22 */:
                    bool10 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case EventType.AUDIO /* 23 */:
                    bool11 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case EventType.VIDEO /* 24 */:
                    bool12 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case EventType.SUBS /* 25 */:
                    str6 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case EventType.CDN /* 26 */:
                    str7 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 27:
                    l7 = (Long) lVar2.a(reader);
                    l = l8;
                    str = str10;
                case 28:
                    bool13 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 29:
                    bool14 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 30:
                    bool15 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 31:
                    bool16 = (Boolean) lVar4.a(reader);
                    l = l8;
                    str = str10;
                case 32:
                    str8 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                case 33:
                    str9 = (String) lVar3.a(reader);
                    l = l8;
                    str = str10;
                default:
                    l = l8;
                    str = str10;
            }
        }
        Long l9 = l;
        String str11 = str;
        reader.i();
        if (l9 != null) {
            return new RemoteFullUser(l9.longValue(), str11, l2, l3, num, bool, bool2, bool3, str2, str3, l4, l5, l6, bool4, num2, str4, str5, bool5, bool6, bool7, bool8, bool9, bool10, bool11, bool12, str6, str7, l7, bool13, bool14, bool15, bool16, str8, str9);
        }
        throw b.e("id", "id", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteFullUser remoteFullUser = (RemoteFullUser) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteFullUser == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteFullUser.a));
        writer.l("username");
        l lVar = this.c;
        lVar.g(writer, remoteFullUser.b);
        writer.l("timestamp");
        l lVar2 = this.d;
        lVar2.g(writer, remoteFullUser.c);
        writer.l("lastModified");
        lVar2.g(writer, remoteFullUser.d);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        l lVar3 = this.e;
        lVar3.g(writer, remoteFullUser.e);
        writer.l(DBUserFields.Names.IS_VERIFIED);
        l lVar4 = this.f;
        lVar4.g(writer, remoteFullUser.f);
        writer.l(DBUserFields.Names.IS_ADMIN);
        lVar4.g(writer, remoteFullUser.g);
        writer.l("isLocked");
        lVar4.g(writer, remoteFullUser.h);
        writer.l("_imageUrl");
        lVar.g(writer, remoteFullUser.i);
        writer.l(DBUserFields.Names.TIME_ZONE);
        lVar.g(writer, remoteFullUser.j);
        writer.l("birthYear");
        lVar2.g(writer, remoteFullUser.k);
        writer.l("birthMonth");
        lVar2.g(writer, remoteFullUser.l);
        writer.l("birthDay");
        lVar2.g(writer, remoteFullUser.m);
        writer.l("isConfirmed");
        lVar4.g(writer, remoteFullUser.n);
        writer.l(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE);
        lVar3.g(writer, remoteFullUser.o);
        writer.l(DBUserFields.Names.PROFILE_IMAGE_ID);
        lVar.g(writer, remoteFullUser.p);
        writer.l("email");
        lVar.g(writer, remoteFullUser.q);
        writer.l("_hasPassword");
        lVar4.g(writer, remoteFullUser.r);
        writer.l("_hasFacebook");
        lVar4.g(writer, remoteFullUser.s);
        writer.l("_hasGoogle");
        lVar4.g(writer, remoteFullUser.t);
        writer.l("_isConfirmationRequired");
        lVar4.g(writer, remoteFullUser.u);
        writer.l("_canChangeUsername");
        lVar4.g(writer, remoteFullUser.v);
        writer.l("_isUnderAge");
        lVar4.g(writer, remoteFullUser.w);
        writer.l("_isUnderAgeForAds");
        lVar4.g(writer, remoteFullUser.x);
        writer.l("_needsChildDirectedTreatment");
        lVar4.g(writer, remoteFullUser.y);
        writer.l("mobileLocale");
        lVar.g(writer, remoteFullUser.z);
        writer.l("userLocalePreference");
        lVar.g(writer, remoteFullUser.A);
        writer.l(DBUserFields.Names.NOTIFICATION_TIME);
        lVar2.g(writer, remoteFullUser.B);
        writer.l(DBUserFields.Names.NOTIFICATIONS_ENABLED);
        lVar4.g(writer, remoteFullUser.C);
        writer.l("_isEligibleForFreeTrial");
        lVar4.g(writer, remoteFullUser.D);
        writer.l("_hasOptedIntoFreeOfflinePromo");
        lVar4.g(writer, remoteFullUser.E);
        writer.l(DBUserFields.Names.IS_SELF_LEARNER);
        lVar4.g(writer, remoteFullUser.F);
        writer.l(DBUserFields.Names.SIGNUP_COUNTRY_CODE);
        lVar.g(writer, remoteFullUser.G);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar.g(writer, remoteFullUser.H);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteFullUser)", "toString(...)");
    }
}
