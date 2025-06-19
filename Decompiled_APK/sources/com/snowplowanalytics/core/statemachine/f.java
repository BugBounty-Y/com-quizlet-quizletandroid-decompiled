package com.snowplowanalytics.core.statemachine;

import com.snowplowanalytics.core.tracker.q;
import java.util.List;
import java.util.Map;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public interface f {
    List a();

    void b(q qVar);

    List c();

    List d();

    d e(com.snowplowanalytics.snowplow.event.a aVar, d dVar);

    List f();

    List g(com.snowplowanalytics.snowplow.event.a aVar);

    String getIdentifier();

    Boolean h(q qVar, d dVar);

    List i(q qVar, d dVar);

    K j();

    List k();

    Map l(q qVar, d dVar);
}
