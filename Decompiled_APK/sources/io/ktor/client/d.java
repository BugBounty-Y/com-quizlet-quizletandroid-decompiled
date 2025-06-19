package io.ktor.client;

import io.ktor.client.plugins.InterfaceC4874v;
import io.ktor.util.k;
import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final LinkedHashMap a = new LinkedHashMap();
    public final LinkedHashMap b = new LinkedHashMap();
    public final LinkedHashMap c = new LinkedHashMap();
    public Function1 d = new com.sdk.growthbook.utils.a(2);
    public boolean e = true;
    public boolean f = true;

    public d() {
        int i = k.a;
    }

    public final void a(InterfaceC4874v plugin, Function1 configure) {
        Intrinsics.checkNotNullParameter(plugin, "plugin");
        Intrinsics.checkNotNullParameter(configure, "configure");
        LinkedHashMap linkedHashMap = this.b;
        linkedHashMap.put(plugin.getKey(), new com.quizlet.features.practicetest.takingtest.b((Function1) linkedHashMap.get(plugin.getKey()), configure, 2));
        LinkedHashMap linkedHashMap2 = this.a;
        if (linkedHashMap2.containsKey(plugin.getKey())) {
            return;
        }
        linkedHashMap2.put(plugin.getKey(), new com.quizlet.ui.compose.modifiers.b(plugin, 2));
    }
}
