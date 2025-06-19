package io.ktor.client.plugins.api;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final io.ktor.client.c a;
    public final Object b;
    public final ArrayList c;
    public final b d;

    public c(io.ktor.util.a key, io.ktor.client.c client, Object pluginConfig) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(pluginConfig, "pluginConfig");
        this.a = client;
        this.b = pluginConfig;
        this.c = new ArrayList();
        this.d = new b(0);
    }

    public final void a(a hook, kotlin.coroutines.jvm.internal.i iVar) {
        Intrinsics.checkNotNullParameter(hook, "hook");
        this.c.add(new f(hook, iVar));
    }
}
