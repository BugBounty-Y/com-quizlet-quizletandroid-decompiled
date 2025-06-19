package com.quizlet.remote.model.achievements;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
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
public final class BadgeDataResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public BadgeDataResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("badgeId", OTUXParamsKeys.OT_UX_DESCRIPTION, "goalType", "goal", "goalCategory", "name", "imageUrl", "winDate", "goalTextAlignment");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "badgeId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "goal");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(BadgeImageUrlResponse.class, m, "imageUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Long.class, m, "winDate");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(String.class, m, "goalTextAlignment");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
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
        Long l = null;
        String str6 = null;
        while (true) {
            Integer num2 = num;
            String str7 = str;
            if (!reader.l()) {
                String str8 = str2;
                reader.i();
                if (str7 == null) {
                    throw com.squareup.moshi.internal.b.e("badgeId", "badgeId", reader);
                }
                if (str8 == null) {
                    throw com.squareup.moshi.internal.b.e(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                }
                if (str3 == null) {
                    throw com.squareup.moshi.internal.b.e("goalType", "goalType", reader);
                }
                if (num2 == null) {
                    throw com.squareup.moshi.internal.b.e("goal", "goal", reader);
                }
                int iIntValue = num2.intValue();
                if (str4 == null) {
                    throw com.squareup.moshi.internal.b.e("goalCategory", "goalCategory", reader);
                }
                if (str5 == null) {
                    throw com.squareup.moshi.internal.b.e("name", "name", reader);
                }
                if (badgeImageUrlResponse != null) {
                    return new BadgeDataResponse(str7, str8, str3, iIntValue, str4, str5, badgeImageUrlResponse, l, str6);
                }
                throw com.squareup.moshi.internal.b.e("imageUrl", "imageUrl", reader);
            }
            String str9 = str2;
            int iK0 = reader.k0(this.a);
            l lVar = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 0:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("badgeId", "badgeId", reader);
                    }
                    num = num2;
                    str2 = str9;
                case 1:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k(OTUXParamsKeys.OT_UX_DESCRIPTION, OTUXParamsKeys.OT_UX_DESCRIPTION, reader);
                    }
                    num = num2;
                    str = str7;
                case 2:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("goalType", "goalType", reader);
                    }
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 3:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("goal", "goal", reader);
                    }
                    str2 = str9;
                    str = str7;
                case 4:
                    str4 = (String) lVar.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("goalCategory", "goalCategory", reader);
                    }
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 5:
                    str5 = (String) lVar.a(reader);
                    if (str5 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 6:
                    badgeImageUrlResponse = (BadgeImageUrlResponse) this.d.a(reader);
                    if (badgeImageUrlResponse == null) {
                        throw com.squareup.moshi.internal.b.k("imageUrl", "imageUrl", reader);
                    }
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 7:
                    l = (Long) this.e.a(reader);
                    num = num2;
                    str2 = str9;
                    str = str7;
                case 8:
                    str6 = (String) this.f.a(reader);
                    num = num2;
                    str2 = str9;
                    str = str7;
                default:
                    num = num2;
                    str2 = str9;
                    str = str7;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        BadgeDataResponse badgeDataResponse = (BadgeDataResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (badgeDataResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("badgeId");
        String str = badgeDataResponse.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar.g(writer, badgeDataResponse.b);
        writer.l("goalType");
        lVar.g(writer, badgeDataResponse.c);
        writer.l("goal");
        this.c.g(writer, Integer.valueOf(badgeDataResponse.d));
        writer.l("goalCategory");
        lVar.g(writer, badgeDataResponse.e);
        writer.l("name");
        lVar.g(writer, badgeDataResponse.f);
        writer.l("imageUrl");
        this.d.g(writer, badgeDataResponse.g);
        writer.l("winDate");
        this.e.g(writer, badgeDataResponse.h);
        writer.l("goalTextAlignment");
        this.f.g(writer, badgeDataResponse.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(BadgeDataResponse)", "toString(...)");
    }
}
