package com.quizlet.generated.enums;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.generated.enums.n0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4504n0 {
    public static EnumC4507o0 a(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        for (EnumC4507o0 enumC4507o0 : EnumC4507o0.values()) {
            if (Intrinsics.b(enumC4507o0.a(), value)) {
                return enumC4507o0;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
