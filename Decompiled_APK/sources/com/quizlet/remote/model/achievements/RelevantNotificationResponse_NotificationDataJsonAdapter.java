package com.quizlet.remote.model.achievements;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.remote.model.achievements.RelevantNotificationResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RelevantNotificationResponse_NotificationDataJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public RelevantNotificationResponse_NotificationDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("achievementId", DBUserFields.Names.USER_UPGRADE_TYPE, "winDate", "goal", "name", OTUXParamsKeys.OT_UX_DESCRIPTION, "imageUrl", "theme", "goalTextAlignment");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "achievementId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "winDate");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, "goal");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(BadgeImageUrlResponse.class, m, "imageUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        BadgeImageUrlResponse badgeImageUrlResponse = null;
        String str6 = null;
        String str7 = null;
        while (true) {
            Integer num2 = num;
            String str8 = str;
            if (!reader.l()) {
                String str9 = str2;
                String str10 = str3;
                reader.i();
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("achievementId", "achievementId", reader);
                }
                if (str9 == null) {
                    throw com.squareup.moshi.internal.b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                }
                if (num2 == null) {
                    throw com.squareup.moshi.internal.b.e("goal", "goal", reader);
                }
                int iIntValue = num2.intValue();
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (badgeImageUrlResponse == null) {
                    throw com.squareup.moshi.internal.b.e("imageUrl", "imageUrl", reader);
                }
                if (str6 != null) {
                    return new RelevantNotificationResponse.NotificationData(str8, str9, str10, iIntValue, str4, str5, badgeImageUrlResponse, str6, str7);
                }
                throw com.squareup.moshi.internal.b.e("theme", "theme", reader);
            }
            String str11 = str2;
            int iK0 = reader.k0(this.a);
            l lVar = this.c;
            String str12 = str3;
            l lVar2 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 0:
                    str = (String) lVar2.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("achievementId", "achievementId", reader);
                    }
                    num = num2;
                    str2 = str11;
                    str3 = str12;
                case 1:
                    str2 = (String) lVar2.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                    }
                    num = num2;
                    str = str8;
                    str3 = str12;
                case 2:
                    str3 = (String) lVar.a(reader);
                    num = num2;
                    str2 = str11;
                    str = str8;
                case 3:
                    num = (Integer) this.d.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("goal", "goal", reader);
                    }
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 4:
                    str4 = (String) lVar2.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 5:
                    str5 = (String) lVar2.a(reader);
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 6:
                    badgeImageUrlResponse = (BadgeImageUrlResponse) this.e.a(reader);
                    if (badgeImageUrlResponse == null) {
                        throw com.squareup.moshi.internal.b.k("imageUrl", "imageUrl", reader);
                    }
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 7:
                    str6 = (String) lVar2.a(reader);
                    if (str6 == null) {
                        throw com.squareup.moshi.internal.b.k("theme", "theme", reader);
                    }
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                case 8:
                    str7 = (String) lVar.a(reader);
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
                default:
                    num = num2;
                    str2 = str11;
                    str = str8;
                    str3 = str12;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RelevantNotificationResponse.NotificationData notificationData = (RelevantNotificationResponse.NotificationData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (notificationData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("achievementId");
        String str = notificationData.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        lVar.g(writer, notificationData.b);
        writer.l("winDate");
        l lVar2 = this.c;
        lVar2.g(writer, notificationData.c);
        writer.l("goal");
        this.d.g(writer, Integer.valueOf(notificationData.d));
        writer.l("name");
        lVar.g(writer, notificationData.e);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar.g(writer, notificationData.f);
        writer.l("imageUrl");
        this.e.g(writer, notificationData.g);
        writer.l("theme");
        lVar.g(writer, notificationData.h);
        writer.l("goalTextAlignment");
        lVar2.g(writer, notificationData.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(67, "GeneratedJsonAdapter(RelevantNotificationResponse.NotificationData)", "toString(...)");
    }
}
