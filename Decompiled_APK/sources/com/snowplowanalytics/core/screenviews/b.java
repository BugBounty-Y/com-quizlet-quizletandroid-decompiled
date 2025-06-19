package com.snowplowanalytics.core.screenviews;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.snowplowanalytics.core.statemachine.d;
import com.snowplowanalytics.core.statemachine.f;
import com.snowplowanalytics.core.tracker.q;
import com.snowplowanalytics.snowplow.event.e;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements f {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List a() {
        switch (this.a) {
        }
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final void b(q event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List c() {
        switch (this.a) {
        }
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List d() {
        switch (this.a) {
            case 0:
                return A.b("*");
            case 1:
                return B.j("iglu:com.snowplowanalytics.mobile/screen_end/jsonschema/1-0-0", "iglu:com.snowplowanalytics.snowplow/application_foreground/jsonschema/1-0-0", "iglu:com.snowplowanalytics.snowplow/application_background/jsonschema/1-0-0");
            case 2:
                return A.b("iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0");
            default:
                return A.b("*");
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final d e(com.snowplowanalytics.snowplow.event.a event, d dVar) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                e eVar = event instanceof e ? (e) event : null;
                if (eVar == null) {
                    return null;
                }
                return new a(eVar.b, eVar.d, eVar.c, eVar.e, eVar.f, dVar instanceof a ? (a) dVar : null);
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                if (event instanceof e) {
                    c cVar = new c();
                    cVar.a = System.currentTimeMillis();
                    return cVar;
                }
                c cVar2 = (c) dVar;
                if (cVar2 == null) {
                    return null;
                }
                if (event instanceof com.snowplowanalytics.snowplow.event.c) {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    cVar2.c = (jCurrentTimeMillis - cVar2.a) + cVar2.c;
                    cVar2.a = jCurrentTimeMillis;
                    return dVar;
                }
                if (event instanceof com.snowplowanalytics.snowplow.event.b) {
                    long jCurrentTimeMillis2 = System.currentTimeMillis();
                    cVar2.b = (jCurrentTimeMillis2 - cVar2.a) + cVar2.b;
                    cVar2.a = jCurrentTimeMillis2;
                    return dVar;
                }
                if (!(event instanceof com.snowplowanalytics.snowplow.event.d)) {
                    return dVar;
                }
                long jCurrentTimeMillis3 = System.currentTimeMillis();
                cVar2.b = (jCurrentTimeMillis3 - cVar2.a) + cVar2.b;
                cVar2.a = jCurrentTimeMillis3;
                return dVar;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                if (dVar != null && (dVar instanceof com.snowplowanalytics.core.statemachine.a)) {
                }
                return null;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                if (event instanceof com.snowplowanalytics.snowplow.event.c) {
                    return new com.snowplowanalytics.core.statemachine.b(true, ((com.snowplowanalytics.snowplow.event.c) event).b);
                }
                if (event instanceof com.snowplowanalytics.snowplow.event.b) {
                    return new com.snowplowanalytics.core.statemachine.b(false, ((com.snowplowanalytics.snowplow.event.b) event).b);
                }
                return null;
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List f() {
        switch (this.a) {
            case 0:
                return A.b("iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0");
            case 1:
                return K.a;
            case 2:
                return new ArrayList();
            default:
                return K.a;
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List g(com.snowplowanalytics.snowplow.event.a event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
        }
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final String getIdentifier() {
        switch (this.a) {
            case 0:
                return "ScreenContext";
            case 1:
                return "ScreenSummaryContext";
            case 2:
                return "DeepLinkContext";
            default:
                return "Lifecycle";
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final Boolean h(q event, d dVar) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                if (!Intrinsics.b(event.a, "iglu:com.snowplowanalytics.mobile/screen_end/jsonschema/1-0-0")) {
                    break;
                } else {
                    break;
                }
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
        }
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List i(q event, d dVar) {
        com.snowplowanalytics.snowplow.payload.a aVar;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                if (dVar != null) {
                    a aVar2 = dVar instanceof a ? (a) dVar : null;
                    if (aVar2 != null) {
                        com.snowplowanalytics.snowplow.payload.b bVar = new com.snowplowanalytics.snowplow.payload.b();
                        bVar.a("id", aVar2.c);
                        bVar.a("name", aVar2.a);
                        bVar.a(DBUserFields.Names.USER_UPGRADE_TYPE, aVar2.b);
                        bVar.a("fragment", null);
                        String str = aVar2.d;
                        if ((str == null || str.length() <= 0) && ((str = aVar2.e) == null || str.length() <= 0)) {
                            str = null;
                        }
                        bVar.a("activity", str);
                        aVar = new com.snowplowanalytics.snowplow.payload.a(bVar);
                    } else {
                        aVar = null;
                    }
                    if (aVar == null) {
                        break;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                if (((c) dVar) != null) {
                    break;
                }
                break;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                if (dVar != null && (dVar instanceof com.snowplowanalytics.core.statemachine.a)) {
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                if (dVar != null) {
                    com.snowplowanalytics.core.statemachine.b bVar2 = dVar instanceof com.snowplowanalytics.core.statemachine.b ? (com.snowplowanalytics.core.statemachine.b) dVar : null;
                    if (bVar2 == null) {
                        break;
                    } else {
                        com.snowplowanalytics.snowplow.entity.c cVar = new com.snowplowanalytics.snowplow.entity.c(bVar2.a);
                        HashMap map = cVar.b;
                        Integer num = bVar2.b;
                        if (num != null) {
                            map.put("index", Integer.valueOf(num.intValue()));
                        }
                        cVar.a(map);
                        break;
                    }
                } else {
                    break;
                }
        }
        return null;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final K j() {
        switch (this.a) {
        }
        return K.a;
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final List k() {
        switch (this.a) {
            case 0:
                return A.b("iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0");
            case 1:
                return B.j("iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0", "iglu:com.snowplowanalytics.mobile/screen_end/jsonschema/1-0-0", "iglu:com.snowplowanalytics.snowplow/application_foreground/jsonschema/1-0-0", "iglu:com.snowplowanalytics.snowplow/application_background/jsonschema/1-0-0", "iglu:com.snowplowanalytics.mobile/list_item_view/jsonschema/1-0-0", "iglu:com.snowplowanalytics.mobile/scroll_changed/jsonschema/1-0-0");
            case 2:
                return B.j("iglu:com.snowplowanalytics.mobile/deep_link_received/jsonschema/1-0-0", "iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0");
            default:
                return B.j("iglu:com.snowplowanalytics.snowplow/application_background/jsonschema/1-0-0", "iglu:com.snowplowanalytics.snowplow/application_foreground/jsonschema/1-0-0");
        }
    }

    @Override // com.snowplowanalytics.core.statemachine.f
    public final Map l(q event, d dVar) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(event, "event");
                if (dVar instanceof a) {
                    HashMap map = new HashMap();
                    a aVar = (a) dVar;
                    a aVar2 = aVar.f;
                    String str = aVar2 != null ? aVar2.a : null;
                    if (str != null && str.length() > 0) {
                        map.put("previousName", str);
                    }
                    a aVar3 = aVar.f;
                    String str2 = aVar3 != null ? aVar3.c : null;
                    if (str2 != null && str2.length() > 0) {
                        map.put("previousId", str2);
                    }
                    String str3 = aVar3 != null ? aVar3.b : null;
                    if (str3 != null && str3.length() > 0) {
                        map.put("previousType", str3);
                    }
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
            default:
                Intrinsics.checkNotNullParameter(event, "event");
                break;
        }
        return null;
    }
}
