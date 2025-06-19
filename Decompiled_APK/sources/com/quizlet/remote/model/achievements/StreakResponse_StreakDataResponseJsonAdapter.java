package com.quizlet.remote.model.achievements;

import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.achievements.StreakResponse;
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
public final class StreakResponse_StreakDataResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;

    public StreakResponse_StreakDataResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("progressType", "count", "expirationDate", "hasShownModal", "startDate", "status", "name", OTUXParamsKeys.OT_UX_DESCRIPTION, "imageUrl", "goalTextAlignment");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "progressType");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "count");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.TYPE, m, "expirationDate");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "hasShownModal");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(BadgeImageUrlResponse.class, m, "imageUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(String.class, m, "goalTextAlignment");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Long l = null;
        String str = null;
        Boolean bool = null;
        Long l2 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        BadgeImageUrlResponse badgeImageUrlResponse = null;
        String str5 = null;
        while (true) {
            Integer num2 = num;
            Long l3 = l;
            String str6 = str;
            Boolean bool2 = bool;
            Long l4 = l2;
            if (!reader.l()) {
                String str7 = str2;
                String str8 = str3;
                reader.i();
                if (str6 == null) {
                    throw com.squareup.moshi.internal.b.e("progressType", "progressType", reader);
                }
                if (num2 == null) {
                    throw com.squareup.moshi.internal.b.e("count", "count", reader);
                }
                int iIntValue = num2.intValue();
                if (l3 == null) {
                    throw com.squareup.moshi.internal.b.e("expirationDate", "expirationDate", reader);
                }
                long jLongValue = l3.longValue();
                if (bool2 == null) {
                    throw com.squareup.moshi.internal.b.e("hasShownModal", "hasShownModal", reader);
                }
                boolean zBooleanValue = bool2.booleanValue();
                if (l4 == null) {
                    throw com.squareup.moshi.internal.b.e("startDate", "startDate", reader);
                }
                long jLongValue2 = l4.longValue();
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("status", "status", reader);
                }
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (badgeImageUrlResponse != null) {
                    return new StreakResponse.StreakDataResponse(str6, iIntValue, jLongValue, zBooleanValue, jLongValue2, str7, str8, str4, badgeImageUrlResponse, str5);
                }
                throw com.squareup.moshi.internal.b.e("imageUrl", "imageUrl", reader);
            }
            String str9 = str2;
            int iK0 = reader.k0(this.a);
            l lVar = this.d;
            String str10 = str3;
            l lVar2 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 0:
                    str = (String) lVar2.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("progressType", "progressType", reader);
                    }
                    num = num2;
                    l = l3;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 1:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("count", "count", reader);
                    }
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 2:
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("expirationDate", "expirationDate", reader);
                    }
                    num = num2;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 3:
                    bool = (Boolean) this.e.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("hasShownModal", "hasShownModal", reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 4:
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("startDate", "startDate", reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    str2 = str9;
                    str3 = str10;
                case 5:
                    str2 = (String) lVar2.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("status", "status", reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str3 = str10;
                case 6:
                    str3 = (String) lVar2.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                case 7:
                    str4 = (String) lVar2.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 8:
                    badgeImageUrlResponse = (BadgeImageUrlResponse) this.f.a(reader);
                    if (badgeImageUrlResponse == null) {
                        throw com.squareup.moshi.internal.b.k("imageUrl", "imageUrl", reader);
                    }
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                case 9:
                    str5 = (String) this.g.a(reader);
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
                default:
                    num = num2;
                    l = l3;
                    str = str6;
                    bool = bool2;
                    l2 = l4;
                    str2 = str9;
                    str3 = str10;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StreakResponse.StreakDataResponse streakDataResponse = (StreakResponse.StreakDataResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (streakDataResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("progressType");
        String str = streakDataResponse.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("count");
        this.c.g(writer, Integer.valueOf(streakDataResponse.b));
        writer.l("expirationDate");
        Long lValueOf = Long.valueOf(streakDataResponse.c);
        l lVar2 = this.d;
        lVar2.g(writer, lValueOf);
        writer.l("hasShownModal");
        this.e.g(writer, Boolean.valueOf(streakDataResponse.d));
        writer.l("startDate");
        Z.k(streakDataResponse.e, lVar2, writer, "status");
        lVar.g(writer, streakDataResponse.f);
        writer.l("name");
        lVar.g(writer, streakDataResponse.g);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar.g(writer, streakDataResponse.h);
        writer.l("imageUrl");
        this.f.g(writer, streakDataResponse.i);
        writer.l("goalTextAlignment");
        this.g.g(writer, streakDataResponse.j);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(55, "GeneratedJsonAdapter(StreakResponse.StreakDataResponse)", "toString(...)");
    }
}
