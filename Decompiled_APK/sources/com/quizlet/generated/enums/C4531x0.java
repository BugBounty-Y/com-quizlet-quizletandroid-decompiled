package com.quizlet.generated.enums;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.generated.enums.x0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4531x0 {
    public static EnumC4533y0 a(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        for (EnumC4533y0 enumC4533y0 : EnumC4533y0.values()) {
            if (Intrinsics.b(enumC4533y0.a(), value)) {
                return enumC4533y0;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
