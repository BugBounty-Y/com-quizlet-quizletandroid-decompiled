package org.wordpress.aztec.watchers.event.text;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class d {
    public b a;
    public c b;
    public a c;

    public e a() {
        b bVar = this.a;
        if (bVar == null) {
            Intrinsics.m("beforeEventData");
            throw null;
        }
        c cVar = this.b;
        if (cVar == null) {
            Intrinsics.m("onEventData");
            throw null;
        }
        a aVar = this.c;
        if (aVar != null) {
            return new e(bVar, cVar, aVar);
        }
        Intrinsics.m("afterEventData");
        throw null;
    }

    public final void b() {
        if (this.a == null) {
            b bVar = new b(null, 0, 0, 0);
            Intrinsics.checkNotNullParameter(bVar, "<set-?>");
            this.a = bVar;
        }
        if (this.b == null) {
            c cVar = new c(null, 0, 0, 0);
            Intrinsics.checkNotNullParameter(cVar, "<set-?>");
            this.b = cVar;
        }
        if (this.c == null) {
            a aVar = new a(null);
            Intrinsics.checkNotNullParameter(aVar, "<set-?>");
            this.c = aVar;
        }
    }
}
