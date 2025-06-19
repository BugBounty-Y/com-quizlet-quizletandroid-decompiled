package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class N1 {
    public static O1 a(int i) {
        for (O1 o1 : O1.values()) {
            if (o1.a() == i) {
                return o1;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
