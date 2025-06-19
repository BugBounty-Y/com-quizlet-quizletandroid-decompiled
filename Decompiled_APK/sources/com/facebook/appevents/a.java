package com.facebook.appevents;

import java.io.ObjectStreamException;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements Serializable {
    public final String a;
    public final String b;

    public a(String str, String appId) {
        Intrinsics.checkNotNullParameter(appId, "appId");
        this.a = str;
        this.b = appId;
    }

    private final Object readResolve() throws ObjectStreamException {
        return new b(this.a, this.b);
    }
}
