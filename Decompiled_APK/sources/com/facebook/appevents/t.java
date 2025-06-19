package com.facebook.appevents;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t implements Serializable {
    public final HashMap a;

    public t() {
        this.a = new HashMap();
    }

    private final Object writeReplace() throws ObjectStreamException {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            return new s(this.a);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final void a(b accessTokenAppIdPair, List appEvents) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(accessTokenAppIdPair, "accessTokenAppIdPair");
            Intrinsics.checkNotNullParameter(appEvents, "appEvents");
            HashMap map = this.a;
            if (!map.containsKey(accessTokenAppIdPair)) {
                map.put(accessTokenAppIdPair, CollectionsKt.y0(appEvents));
                return;
            }
            List list = (List) map.get(accessTokenAppIdPair);
            if (list != null) {
                list.addAll(appEvents);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public t(HashMap appEventMap) {
        Intrinsics.checkNotNullParameter(appEventMap, "appEventMap");
        HashMap map = new HashMap();
        this.a = map;
        map.putAll(appEventMap);
    }
}
