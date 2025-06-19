package com.snowplowanalytics.snowplow.network;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final int a;
    public final boolean b;
    public final ArrayList c;

    public i(int i, ArrayList eventIds, boolean z) {
        Intrinsics.checkNotNullParameter(eventIds, "eventIds");
        this.a = i;
        this.b = z;
        this.c = eventIds;
    }
}
