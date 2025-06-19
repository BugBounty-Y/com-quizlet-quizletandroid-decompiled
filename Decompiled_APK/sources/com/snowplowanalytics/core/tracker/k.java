package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k {
    public final Activity a;
    public n b;
    public com.snowplowanalytics.core.emitter.a c;
    public l d;
    public o e;
    public com.snowplowanalytics.core.media.controller.a f;
    public final com.snowplowanalytics.snowplow.configuration.i g;
    public final com.snowplowanalytics.snowplow.configuration.e h;
    public final com.snowplowanalytics.snowplow.configuration.h i;
    public final com.snowplowanalytics.snowplow.configuration.b j;
    public final com.snowplowanalytics.snowplow.configuration.g k;
    public final com.snowplowanalytics.snowplow.configuration.c l;
    public final ArrayList m;

    public k(Activity context, com.snowplowanalytics.snowplow.configuration.e networkConfiguration, List configurations) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter("appTracker", "namespace");
        Intrinsics.checkNotNullParameter(networkConfiguration, "networkConfiguration");
        Intrinsics.checkNotNullParameter(configurations, "configurations");
        kotlin.l.b(new j(this, 0));
        kotlin.l.b(new j(this, 2));
        kotlin.l.b(new j(this, 1));
        this.m = new ArrayList();
        this.a = context;
        com.snowplowanalytics.snowplow.configuration.i iVar = new com.snowplowanalytics.snowplow.configuration.i();
        Intrinsics.checkNotNullParameter(iVar, "<set-?>");
        this.g = iVar;
        com.snowplowanalytics.snowplow.configuration.e eVar = new com.snowplowanalytics.snowplow.configuration.e();
        Intrinsics.checkNotNullParameter(eVar, "<set-?>");
        this.h = eVar;
        com.snowplowanalytics.snowplow.configuration.h hVar = new com.snowplowanalytics.snowplow.configuration.h();
        Intrinsics.checkNotNullParameter(hVar, "<set-?>");
        this.i = hVar;
        com.snowplowanalytics.snowplow.configuration.b bVar = new com.snowplowanalytics.snowplow.configuration.b();
        Intrinsics.checkNotNullParameter(bVar, "<set-?>");
        this.j = bVar;
        com.snowplowanalytics.snowplow.configuration.g gVar = new com.snowplowanalytics.snowplow.configuration.g();
        Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        this.k = gVar;
        com.snowplowanalytics.snowplow.configuration.c cVar = new com.snowplowanalytics.snowplow.configuration.c();
        Intrinsics.checkNotNullParameter(cVar, "<set-?>");
        this.l = cVar;
        b().a = networkConfiguration;
        g(configurations);
        d();
    }

    public final com.snowplowanalytics.snowplow.configuration.b a() {
        com.snowplowanalytics.snowplow.configuration.b bVar = this.j;
        if (bVar != null) {
            return bVar;
        }
        Intrinsics.m("emitterConfiguration");
        throw null;
    }

    public final com.snowplowanalytics.snowplow.configuration.e b() {
        com.snowplowanalytics.snowplow.configuration.e eVar = this.h;
        if (eVar != null) {
            return eVar;
        }
        Intrinsics.m("networkConfiguration");
        throw null;
    }

    public final l c() {
        l lVar = this.d;
        if (lVar != null) {
            return lVar;
        }
        com.snowplowanalytics.snowplow.configuration.h hVar = this.i;
        if (hVar == null) {
            Intrinsics.m("subjectConfiguration");
            throw null;
        }
        l lVar2 = new l(this.a, hVar);
        this.d = lVar2;
        return lVar2;
    }

    public final n d() {
        com.snowplowanalytics.core.emitter.a aVar;
        androidx.core.util.a aVarD;
        n nVar = this.b;
        if (nVar != null) {
            return nVar;
        }
        com.snowplowanalytics.core.emitter.a aVar2 = this.c;
        if (aVar2 == null) {
            String strB = b().b();
            if (strB == null) {
                strB = "";
            }
            com.snowplowanalytics.core.emitter.a aVar3 = new com.snowplowanalytics.core.emitter.a(a().f(), this.a, strB, new androidx.credentials.playservices.controllers.BeginSignIn.c(this, 18));
            if (a().n()) {
                aVar3.d.set(true);
            }
            this.c = aVar3;
            aVar = aVar3;
        } else {
            aVar = aVar2;
        }
        n nVar2 = new n(aVar, f().a(), f().o(), f().p(), this.a, new androidx.compose.ui.viewinterop.b(27, c(), this));
        if (f().x() && nVar2.f.compareAndSet(true, false)) {
            nVar2.b();
            nVar2.h.e();
        }
        if (e().e()) {
            nVar2.b();
        }
        com.snowplowanalytics.core.session.c cVar = nVar2.j;
        if (cVar != null && (aVarD = e().d()) != null) {
            cVar.o = aVarD;
        }
        this.b = nVar2;
        return nVar2;
    }

    public final com.snowplowanalytics.snowplow.configuration.g e() {
        com.snowplowanalytics.snowplow.configuration.g gVar = this.k;
        if (gVar != null) {
            return gVar;
        }
        Intrinsics.m("sessionConfiguration");
        throw null;
    }

    public final com.snowplowanalytics.snowplow.configuration.i f() {
        com.snowplowanalytics.snowplow.configuration.i iVar = this.g;
        if (iVar != null) {
            return iVar;
        }
        Intrinsics.m("trackerConfiguration");
        throw null;
    }

    public final void g(List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.snowplowanalytics.snowplow.configuration.a aVar = (com.snowplowanalytics.snowplow.configuration.a) it2.next();
            if (aVar instanceof com.snowplowanalytics.snowplow.configuration.e) {
                b().a = (com.snowplowanalytics.snowplow.configuration.e) aVar;
            } else if (aVar instanceof com.snowplowanalytics.snowplow.configuration.i) {
                f().b = (com.snowplowanalytics.snowplow.configuration.i) aVar;
            } else if (aVar instanceof com.snowplowanalytics.snowplow.configuration.h) {
                com.snowplowanalytics.snowplow.configuration.h hVar = this.i;
                if (hVar == null) {
                    Intrinsics.m("subjectConfiguration");
                    throw null;
                }
                hVar.a = (com.snowplowanalytics.snowplow.configuration.h) aVar;
            } else if (aVar instanceof com.snowplowanalytics.snowplow.configuration.g) {
                e().a = (com.snowplowanalytics.snowplow.configuration.g) aVar;
            } else if (aVar instanceof com.snowplowanalytics.snowplow.configuration.b) {
                a().a = (com.snowplowanalytics.snowplow.configuration.b) aVar;
            } else if (aVar instanceof com.snowplowanalytics.snowplow.configuration.c) {
                com.snowplowanalytics.snowplow.configuration.c cVar = this.l;
                if (cVar == null) {
                    Intrinsics.m("gdprConfiguration");
                    throw null;
                }
                cVar.a = (com.snowplowanalytics.snowplow.configuration.c) aVar;
            } else {
                boolean z = aVar instanceof com.snowplowanalytics.snowplow.configuration.d;
                ArrayList arrayList = this.m;
                if (z) {
                    com.snowplowanalytics.snowplow.configuration.d dVar = (com.snowplowanalytics.snowplow.configuration.d) aVar;
                    dVar.getClass();
                    Map map = dVar.a;
                    ArrayList arrayList2 = new ArrayList(map.size());
                    for (Map.Entry entry : map.entrySet()) {
                        arrayList2.add(new com.snowplowanalytics.core.globalcontexts.a((String) entry.getKey(), (com.snowplowanalytics.snowplow.globalcontexts.a) entry.getValue()));
                    }
                    Iterator it3 = arrayList2.iterator();
                    while (it3.hasNext()) {
                        arrayList.add((com.snowplowanalytics.core.globalcontexts.a) it3.next());
                    }
                } else if (aVar instanceof com.snowplowanalytics.core.globalcontexts.a) {
                    arrayList.add(aVar);
                }
            }
        }
    }
}
