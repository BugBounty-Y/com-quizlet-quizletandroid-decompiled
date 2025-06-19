package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class z1 {
    public static A1 a(int i) {
        for (A1 a1 : A1.values()) {
            if (a1.a() == i) {
                return a1;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
