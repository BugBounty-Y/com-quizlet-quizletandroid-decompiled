package com.quizlet.remote.model.achievements;

import com.quizlet.data.model.C4106a;
import com.quizlet.generated.enums.C4476e;
import com.quizlet.generated.enums.EnumC4473d;
import com.quizlet.generated.enums.EnumC4479f;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public static C4106a a(BadgeDataResponse badgeDataResponse) {
        String str = badgeDataResponse.a;
        C4476e c4476e = EnumC4479f.Companion;
        String str2 = badgeDataResponse.c;
        c4476e.getClass();
        EnumC4479f enumC4479fA = C4476e.a(str2);
        EnumC4473d.Companion.getClass();
        String value = badgeDataResponse.e;
        Intrinsics.checkNotNullParameter(value, "value");
        EnumC4473d[] enumC4473dArrValues = EnumC4473d.values();
        int length = enumC4473dArrValues.length;
        int i = 0;
        while (i < length) {
            int i2 = length;
            EnumC4473d enumC4473d = enumC4473dArrValues[i];
            if (Intrinsics.b(enumC4473d.a(), value)) {
                String background = badgeDataResponse.g.b;
                Intrinsics.checkNotNullParameter(background, "background");
                return new C4106a(str, badgeDataResponse.b, enumC4479fA, badgeDataResponse.d, enumC4473d, badgeDataResponse.f, background, badgeDataResponse.i, badgeDataResponse.h);
            }
            i++;
            length = i2;
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
