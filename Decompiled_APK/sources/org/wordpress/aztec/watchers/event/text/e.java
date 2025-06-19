package org.wordpress.aztec.watchers.event.text;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class e {
    public b a;
    public c b;
    public a c;
    public final long d;

    public e(b beforeEventData, c onEventData, a afterEventData) {
        Intrinsics.checkNotNullParameter(beforeEventData, "beforeEventData");
        Intrinsics.checkNotNullParameter(onEventData, "onEventData");
        Intrinsics.checkNotNullParameter(afterEventData, "afterEventData");
        this.a = beforeEventData;
        this.b = onEventData;
        this.c = afterEventData;
        this.d = System.currentTimeMillis();
    }

    public boolean a() {
        return false;
    }
}
