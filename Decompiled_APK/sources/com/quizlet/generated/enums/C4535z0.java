package com.quizlet.generated.enums;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.generated.enums.z0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4535z0 {
    public static A0 a(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        for (A0 a0 : A0.values()) {
            if (Intrinsics.b(a0.a(), value)) {
                return a0;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
