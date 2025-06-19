package com.snowplowanalytics.snowplow.network;

import android.content.Context;
import java.util.EnumSet;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.n;

/* loaded from: classes3.dex */
public final class e {
    public final String a;
    public final Context b;
    public c c;
    public EnumSet d;
    public int e;
    public A f;
    public n g;
    public String h;
    public boolean i;
    public Map j;

    public e(String uri, Context context) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = uri;
        this.b = context;
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        this.c = c.b;
        this.d = com.snowplowanalytics.core.emitter.b.a;
        this.e = com.snowplowanalytics.core.emitter.b.g;
        this.i = false;
    }

    public final void a(c httpMethod) {
        Intrinsics.checkNotNullParameter(httpMethod, "httpMethod");
        this.c = httpMethod;
    }

    public final void b(EnumSet versions) {
        Intrinsics.checkNotNullParameter(versions, "versions");
        this.d = versions;
    }
}
