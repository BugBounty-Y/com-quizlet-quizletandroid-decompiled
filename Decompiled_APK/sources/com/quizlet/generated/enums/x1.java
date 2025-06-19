package com.quizlet.generated.enums;

import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class x1 {
    public static y1 a(int i) {
        for (y1 y1Var : y1.values()) {
            if (y1Var.b() == i) {
                return y1Var;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }
}
