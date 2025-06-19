package com.quizlet.generated.enums;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.generated.enums.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4476e {
    public static EnumC4479f a(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        for (EnumC4479f enumC4479f : EnumC4479f.values()) {
            if (Intrinsics.b(enumC4479f.a(), value)) {
                return enumC4479f;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
