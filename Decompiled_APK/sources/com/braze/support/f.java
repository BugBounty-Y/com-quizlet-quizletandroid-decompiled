package com.braze.support;

import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public static final f a = new f();

    public static final String a(String str) {
        return AbstractC1484j.a("Failed to create valid enum from string: ", str);
    }

    public static final EnumSet a(Class targetEnumClass, Set sourceStringSet) {
        Intrinsics.checkNotNullParameter(targetEnumClass, "targetEnumClass");
        Intrinsics.checkNotNullParameter(sourceStringSet, "sourceStringSet");
        EnumSet enumSetNoneOf = EnumSet.noneOf(targetEnumClass);
        Iterator it2 = sourceStringSet.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            try {
                Locale US = Locale.US;
                Intrinsics.checkNotNullExpressionValue(US, "US");
                String enumValue = str.toUpperCase(US);
                Intrinsics.checkNotNullExpressionValue(enumValue, "toUpperCase(...)");
                Intrinsics.checkNotNullParameter(enumValue, "enumValue");
                Intrinsics.checkNotNullParameter(targetEnumClass, "targetEnumClass");
                enumSetNoneOf.add(Enum.valueOf(targetEnumClass, enumValue));
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new w(str, 9), 4, (Object) null);
            }
        }
        Intrinsics.d(enumSetNoneOf);
        return enumSetNoneOf;
    }

    public static final Set a(EnumSet sourceEnumSet) {
        Intrinsics.checkNotNullParameter(sourceEnumSet, "sourceEnumSet");
        ArrayList arrayList = new ArrayList(C.q(sourceEnumSet, 10));
        Iterator it2 = sourceEnumSet.iterator();
        while (it2.hasNext()) {
            arrayList.add(((Enum) it2.next()).name());
        }
        return CollectionsKt.A0(arrayList);
    }
}
