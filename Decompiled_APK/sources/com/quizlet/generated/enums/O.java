package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class O {
    public static P a(int i) {
        for (P p : P.values()) {
            if (p.a() == i) {
                return p;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
