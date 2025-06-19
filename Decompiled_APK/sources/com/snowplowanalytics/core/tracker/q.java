package com.snowplowanalytics.core.tracker;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q {
    public final String a;
    public final HashMap b;
    public final com.quizlet.quizletandroid.k c;
    public final ArrayList d;
    public final UUID e;
    public final long f;
    public final boolean g;

    public q(com.snowplowanalytics.snowplow.event.a event, com.quizlet.quizletandroid.k kVar) {
        Intrinsics.checkNotNullParameter(event, "event");
        UUID uuidRandomUUID = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID()");
        this.e = uuidRandomUUID;
        this.f = System.currentTimeMillis();
        ArrayList arrayListY0 = CollectionsKt.y0(event.a);
        Intrinsics.checkNotNullParameter(arrayListY0, "<set-?>");
        this.d = arrayListY0;
        HashMap map = new HashMap(V.l(event.a()));
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.b = map;
        Intrinsics.checkNotNullParameter(kVar, "<set-?>");
        this.c = kVar;
        this.g = event instanceof com.snowplowanalytics.snowplow.event.g;
        event = event instanceof com.snowplowanalytics.snowplow.event.a ? event : null;
        this.a = event != null ? event.b() : null;
    }

    public final void a(com.snowplowanalytics.snowplow.payload.a entity) {
        Intrinsics.checkNotNullParameter(entity, "entity");
        ((ArrayList) b()).add(entity);
    }

    public final List b() {
        ArrayList arrayList = this.d;
        if (arrayList != null) {
            return arrayList;
        }
        Intrinsics.m("entities");
        throw null;
    }

    public final Map c() {
        HashMap map = this.b;
        if (map != null) {
            return map;
        }
        Intrinsics.m("payload");
        throw null;
    }
}
