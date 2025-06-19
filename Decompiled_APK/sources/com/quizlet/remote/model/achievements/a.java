package com.quizlet.remote.model.achievements;

import com.google.android.gms.internal.appset.e;
import com.quizlet.data.model.C4106a;
import com.quizlet.data.model.C4118d;
import com.quizlet.data.model.C4121d2;
import com.quizlet.data.model.C4131h;
import com.quizlet.data.model.C4143l;
import com.quizlet.data.model.C4149n;
import com.quizlet.data.model.C4155p;
import com.quizlet.data.model.e2;
import com.quizlet.generated.enums.C4476e;
import com.quizlet.generated.enums.EnumC4479f;
import com.quizlet.generated.enums.EnumC4485h;
import com.quizlet.remote.model.achievements.RelevantNotificationResponse;
import com.quizlet.remote.model.achievements.StreakResponse;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    public /* synthetic */ a(e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C4143l c4143l;
        switch (this.a) {
            case 0:
                RelevantNotificationResponse remote = (RelevantNotificationResponse) obj;
                Intrinsics.checkNotNullParameter(remote, "it");
                Object obj2 = this.b.c;
                Intrinsics.checkNotNullParameter(remote, "remote");
                RelevantNotificationResponse.NotificationData notificationData = remote.d;
                if (notificationData != null) {
                    EnumC4485h.Companion.getClass();
                    String value = notificationData.b;
                    Intrinsics.checkNotNullParameter(value, "value");
                    EnumC4485h[] enumC4485hArrValues = EnumC4485h.values();
                    int length = enumC4485hArrValues.length;
                    int i = 0;
                    while (i < length) {
                        EnumC4485h[] enumC4485hArr = enumC4485hArrValues;
                        EnumC4485h enumC4485h = enumC4485hArr[i];
                        if (Intrinsics.b(enumC4485h.a(), value)) {
                            c4143l = new C4143l(notificationData.a, enumC4485h, notificationData.c, notificationData.d, notificationData.e, notificationData.f, notificationData.g.b, notificationData.h, notificationData.i);
                        } else {
                            i++;
                            enumC4485hArrValues = enumC4485hArr;
                        }
                    }
                    throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
                c4143l = null;
                return c4143l != null ? c4143l : C4149n.a;
            case 1:
                BadgesResponse remote2 = (BadgesResponse) obj;
                Intrinsics.checkNotNullParameter(remote2, "it");
                Object obj3 = this.b.c;
                Intrinsics.checkNotNullParameter(remote2, "remote");
                List list = remote2.d;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(d.a((BadgeDataResponse) it2.next()));
                }
                return new C4131h(arrayList);
            case 2:
                BadgeResponse remote3 = (BadgeResponse) obj;
                Intrinsics.checkNotNullParameter(remote3, "it");
                Object obj4 = this.b.c;
                Intrinsics.checkNotNullParameter(remote3, "remote");
                BadgeDataResponse badgeDataResponse = remote3.d;
                C4106a c4106aA = badgeDataResponse != null ? d.a(badgeDataResponse) : null;
                return c4106aA != null ? c4106aA : C4118d.a;
            case 3:
                StreaksHistoryResponse remote4 = (StreaksHistoryResponse) obj;
                Intrinsics.checkNotNullParameter(remote4, "it");
                Object obj5 = this.b.c;
                Intrinsics.checkNotNullParameter(remote4, "remote");
                List list2 = remote4.d.a;
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                Iterator it3 = list2.iterator();
                while (it3.hasNext()) {
                    LocalDateTime localDateTimeOfInstant = LocalDateTime.ofInstant(Instant.ofEpochSecond(((Number) it3.next()).longValue()), ZoneId.systemDefault());
                    Intrinsics.checkNotNullExpressionValue(localDateTimeOfInstant, "ofInstant(...)");
                    arrayList2.add(localDateTimeOfInstant);
                }
                return new C4155p(arrayList2);
            default:
                StreakResponse remote5 = (StreakResponse) obj;
                Intrinsics.checkNotNullParameter(remote5, "it");
                Object obj6 = this.b.c;
                Intrinsics.checkNotNullParameter(remote5, "remote");
                StreakResponse.StreakDataResponse streakDataResponse = remote5.d;
                if (streakDataResponse == null) {
                    return e2.a;
                }
                C4476e c4476e = EnumC4479f.Companion;
                String str = streakDataResponse.a;
                c4476e.getClass();
                EnumC4479f enumC4479fA = C4476e.a(str);
                LocalDateTime localDateTimeOfInstant2 = LocalDateTime.ofInstant(Instant.ofEpochSecond(streakDataResponse.e), ZoneId.systemDefault());
                Intrinsics.checkNotNullExpressionValue(localDateTimeOfInstant2, "ofInstant(...)");
                LocalDateTime localDateTimeOfInstant3 = LocalDateTime.ofInstant(Instant.ofEpochSecond(streakDataResponse.c), ZoneId.systemDefault());
                Intrinsics.checkNotNullExpressionValue(localDateTimeOfInstant3, "ofInstant(...)");
                String str2 = streakDataResponse.i.b;
                return new C4121d2(enumC4479fA, streakDataResponse.b, streakDataResponse.d, localDateTimeOfInstant2, localDateTimeOfInstant3, streakDataResponse.g, streakDataResponse.h, str2, streakDataResponse.j);
        }
    }
}
