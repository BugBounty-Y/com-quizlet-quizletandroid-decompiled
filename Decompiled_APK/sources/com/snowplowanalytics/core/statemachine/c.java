package com.snowplowanalytics.core.statemachine;

import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import com.snowplowanalytics.core.tracker.q;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements f {
    public final String a;
    public final i b;

    public c(String identifier, i iVar) {
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        this.a = identifier;
        this.b = iVar;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List a() {
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final void b(q event) {
        Intrinsics.checkNotNullParameter(event, "event");
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List c() {
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List d() {
        if (this.b == null) {
            return K.a;
        }
        List listSingletonList = Collections.singletonList("*");
        Intrinsics.checkNotNullExpressionValue(listSingletonList, "singletonList(\"*\")");
        return listSingletonList;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final d e(com.snowplowanalytics.snowplow.event.a event, d dVar) {
        Intrinsics.checkNotNullParameter(event, "event");
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List f() {
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List g(com.snowplowanalytics.snowplow.event.a event) {
        Intrinsics.checkNotNullParameter(event, "event");
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final String getIdentifier() {
        return this.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final Boolean h(q event, d dVar) {
        Intrinsics.checkNotNullParameter(event, "event");
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List i(q event, d dVar) {
        Intrinsics.checkNotNullParameter(event, "event");
        i iVar = this.b;
        List list = iVar != null ? (List) ((com.iabtcf.decoder.d) iVar.b).apply(event) : null;
        return list == null ? K.a : list;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final K j() {
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List k() {
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final Map l(q event, d dVar) {
        Intrinsics.checkNotNullParameter(event, "event");
        return null;
    }
}
