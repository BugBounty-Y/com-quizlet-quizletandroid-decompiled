package com.facebook.appevents;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s implements Serializable {
    public final HashMap a;

    public s(HashMap proxyEvents) {
        Intrinsics.checkNotNullParameter(proxyEvents, "proxyEvents");
        this.a = proxyEvents;
    }

    private final Object readResolve() throws ObjectStreamException {
        return new t(this.a);
    }
}
