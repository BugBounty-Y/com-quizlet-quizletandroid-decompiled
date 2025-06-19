package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class F1 {
    public static G1 a(int i) {
        for (G1 g1 : G1.values()) {
            if (g1.b() == i) {
                return g1;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
