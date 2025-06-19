package com.google.firebase.sessions;

import java.util.Locale;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class W {
    public final f0 a;
    public final g0 b;
    public final String c;
    public int d;
    public N e;

    public W(f0 timeProvider, g0 uuidGenerator) {
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(uuidGenerator, "uuidGenerator");
        this.a = timeProvider;
        this.b = uuidGenerator;
        this.c = a();
        this.d = -1;
    }

    public final String a() {
        this.b.getClass();
        UUID uuidRandomUUID = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID()");
        String string = uuidRandomUUID.toString();
        Intrinsics.checkNotNullExpressionValue(string, "uuidGenerator.next().toString()");
        String lowerCase = kotlin.text.D.o(string, "-", "", false).toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        return lowerCase;
    }
}
