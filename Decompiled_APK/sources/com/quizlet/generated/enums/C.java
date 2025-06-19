package com.quizlet.generated.enums;

/* loaded from: classes3.dex */
public final class C {
    public static D a(Integer num) {
        for (D d : D.values()) {
            int iA = d.a();
            if (num != null && iA == num.intValue()) {
                return d;
            }
        }
        return null;
    }
}
