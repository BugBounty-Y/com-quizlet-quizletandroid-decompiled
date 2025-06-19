package org.wordpress.aztec.watchers.event.sequence.known.space.steps;

import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.watchers.event.text.d;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class a extends d {
    public final /* synthetic */ int d;

    @Override // org.wordpress.aztec.watchers.event.text.d
    public final /* bridge */ /* synthetic */ e a() {
        switch (this.d) {
            case 0:
                return c();
            case 1:
                return d();
            default:
                return e();
        }
    }

    public b c() {
        b();
        org.wordpress.aztec.watchers.event.text.b beforeEventData = this.a;
        if (beforeEventData == null) {
            Intrinsics.m("beforeEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.c onEventData = this.b;
        if (onEventData == null) {
            Intrinsics.m("onEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.a afterEventData = this.c;
        if (afterEventData == null) {
            Intrinsics.m("afterEventData");
            throw null;
        }
        Intrinsics.checkNotNullParameter(beforeEventData, "beforeEventData");
        Intrinsics.checkNotNullParameter(onEventData, "onEventData");
        Intrinsics.checkNotNullParameter(afterEventData, "afterEventData");
        return new b(beforeEventData, onEventData, afterEventData, 0);
    }

    public c d() {
        b();
        org.wordpress.aztec.watchers.event.text.b beforeEventData = this.a;
        if (beforeEventData == null) {
            Intrinsics.m("beforeEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.c onEventData = this.b;
        if (onEventData == null) {
            Intrinsics.m("onEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.a afterEventData = this.c;
        if (afterEventData == null) {
            Intrinsics.m("afterEventData");
            throw null;
        }
        Intrinsics.checkNotNullParameter(beforeEventData, "beforeEventData");
        Intrinsics.checkNotNullParameter(onEventData, "onEventData");
        Intrinsics.checkNotNullParameter(afterEventData, "afterEventData");
        return new c(beforeEventData, onEventData, afterEventData);
    }

    public b e() {
        b();
        org.wordpress.aztec.watchers.event.text.b beforeEventData = this.a;
        if (beforeEventData == null) {
            Intrinsics.m("beforeEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.c onEventData = this.b;
        if (onEventData == null) {
            Intrinsics.m("onEventData");
            throw null;
        }
        org.wordpress.aztec.watchers.event.text.a afterEventData = this.c;
        if (afterEventData == null) {
            Intrinsics.m("afterEventData");
            throw null;
        }
        Intrinsics.checkNotNullParameter(beforeEventData, "beforeEventData");
        Intrinsics.checkNotNullParameter(onEventData, "onEventData");
        Intrinsics.checkNotNullParameter(afterEventData, "afterEventData");
        return new b(beforeEventData, onEventData, afterEventData, 1);
    }
}
