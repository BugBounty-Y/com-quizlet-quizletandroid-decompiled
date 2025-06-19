package io.ktor.client.plugins.api;

import androidx.compose.material.C0574q;
import androidx.paging.C1319i;
import io.ktor.client.plugins.AbstractC4875w;
import io.ktor.client.plugins.C4854a;
import io.ktor.client.plugins.W;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements a {
    public static final h b = new h(0);
    public static final h c = new h(1);
    public static final h d = new h(2);
    public final /* synthetic */ int a;

    public /* synthetic */ h(int i) {
        this.a = i;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.ktor.client.plugins.api.a
    public final void c(io.ktor.client.c client, kotlin.coroutines.jvm.internal.i iVar) {
        kotlin.coroutines.h hVar = null;
        switch (this.a) {
            case 0:
                kotlin.jvm.functions.c handler = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler, "handler");
                C4854a plugin = W.c;
                io.ktor.util.a aVar = AbstractC4875w.a;
                Intrinsics.checkNotNullParameter(client, "<this>");
                Intrinsics.checkNotNullParameter(plugin, "plugin");
                Intrinsics.checkNotNullParameter(client, "<this>");
                Intrinsics.checkNotNullParameter(plugin, "plugin");
                io.ktor.util.e eVar = (io.ktor.util.e) client.i.d(AbstractC4875w.a);
                Object objD = eVar != null ? eVar.d(W.d) : null;
                if (objD != null) {
                    io.ktor.client.engine.c block = new io.ktor.client.engine.c(handler, client, hVar, 2);
                    Intrinsics.checkNotNullParameter(block, "block");
                    ((W) objD).b.add(block);
                    return;
                } else {
                    throw new IllegalStateException("Plugin " + plugin + " is not installed. Consider using `install(" + W.d + ")` in client config first.");
                }
            case 1:
                Function2 handler2 = (Function2) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler2, "handler");
                client.e.f(io.ktor.client.request.f.f, new C0574q(handler2, hVar, 11));
                return;
            default:
                kotlin.jvm.functions.e handler3 = (kotlin.jvm.functions.e) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler3, "handler");
                client.f.f(io.ktor.client.statement.e.h, new C1319i(handler3, hVar, 12));
                return;
        }
    }
}
