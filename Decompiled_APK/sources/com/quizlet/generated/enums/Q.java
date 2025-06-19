package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class Q {
    public static S a(int i) {
        for (S s : S.values()) {
            if (s.a() == i) {
                return s;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
