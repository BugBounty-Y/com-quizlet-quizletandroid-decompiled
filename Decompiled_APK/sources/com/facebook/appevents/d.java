package com.facebook.appevents;

import java.io.ObjectStreamException;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class d implements Serializable {
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;

    public d(String jsonString, String operationalJsonString, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(jsonString, "jsonString");
        Intrinsics.checkNotNullParameter(operationalJsonString, "operationalJsonString");
        this.a = jsonString;
        this.b = operationalJsonString;
        this.c = z;
        this.d = z2;
    }

    private final Object readResolve() throws ObjectStreamException, JSONException {
        return new e(this.a, this.b, this.c, this.d);
    }
}
