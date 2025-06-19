package com.quizlet.generated.enums;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class G {
    public static H a(String str) {
        for (H h : H.values()) {
            if (Intrinsics.b(h.b(), str)) {
                return h;
            }
        }
        return null;
    }
}
