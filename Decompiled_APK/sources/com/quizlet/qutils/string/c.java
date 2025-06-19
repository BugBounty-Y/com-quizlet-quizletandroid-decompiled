package com.quizlet.qutils.string;

import android.util.Patterns;
import java.util.UUID;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public static final c a = new c();

    public static f a(int i, Object... args) {
        Intrinsics.checkNotNullParameter(args, "args");
        return new f(i, C4933y.P(args));
    }

    public static boolean c(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        return Patterns.EMAIL_ADDRESS.matcher(email).matches();
    }

    public String b() {
        UUID uuidRandomUUID = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID(...)");
        String string = uuidRandomUUID.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
