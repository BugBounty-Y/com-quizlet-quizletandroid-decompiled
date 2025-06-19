package io.ktor.client.plugins;

import androidx.paging.C1319i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import java.util.ArrayList;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: io.ktor.client.plugins.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4854a implements io.ktor.client.plugins.api.a, InterfaceC4874v {
    public static final C4854a b = new C4854a(0);
    public static final C4854a c = new C4854a(1);
    public static final C4854a d = new C4854a(2);
    public static final C4854a e = new C4854a(3);
    public static final C4854a f = new C4854a(4);
    public static final C4854a g = new C4854a(5);
    public final /* synthetic */ int a;

    public /* synthetic */ C4854a(int i) {
        this.a = i;
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public void a(Object obj, io.ktor.client.c scope) {
        W plugin = (W) obj;
        Intrinsics.checkNotNullParameter(plugin, "plugin");
        Intrinsics.checkNotNullParameter(scope, "scope");
        scope.e.f(io.ktor.client.request.f.j, new io.ktor.client.engine.c(plugin, scope, null, 1));
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public Object b(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        S s = new S();
        s.a = 20;
        block.invoke(s);
        return new W(s.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.ktor.client.plugins.api.a
    public void c(io.ktor.client.c client, kotlin.coroutines.jvm.internal.i iVar) throws androidx.concurrent.futures.b {
        AbstractC3207m7 abstractC3207m7;
        androidx.sqlite.db.a aVar;
        switch (this.a) {
            case 0:
                Function2 handler = (Function2) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler, "handler");
                client.h.f(io.ktor.client.statement.a.h, new C1319i(handler, (kotlin.coroutines.h) null, 8));
                return;
            case 1:
                kotlin.jvm.functions.c handler2 = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler2, "handler");
                androidx.sqlite.db.a phase = new androidx.sqlite.db.a("ObservableContent", 3);
                io.ktor.client.request.f fVar = client.e;
                androidx.sqlite.db.a reference = io.ktor.client.request.f.i;
                fVar.getClass();
                Intrinsics.checkNotNullParameter(reference, "reference");
                Intrinsics.checkNotNullParameter(phase, "phase");
                kotlin.coroutines.h hVar = null;
                if (!fVar.e(phase)) {
                    int iC = fVar.c(reference);
                    if (iC == -1) {
                        throw new androidx.concurrent.futures.b("Phase " + reference + " was not registered for this pipeline");
                    }
                    int i = iC + 1;
                    ArrayList arrayList = fVar.a;
                    int i2 = kotlin.collections.B.i(arrayList);
                    if (i <= i2) {
                        while (true) {
                            Object obj = arrayList.get(i);
                            io.ktor.util.pipeline.c cVar = obj instanceof io.ktor.util.pipeline.c ? (io.ktor.util.pipeline.c) obj : null;
                            if (cVar != null && (abstractC3207m7 = cVar.b) != null) {
                                io.ktor.util.pipeline.g gVar = abstractC3207m7 instanceof io.ktor.util.pipeline.g ? (io.ktor.util.pipeline.g) abstractC3207m7 : null;
                                if (gVar != null && (aVar = gVar.a) != null && aVar.equals(reference)) {
                                    iC = i;
                                }
                                if (i != i2) {
                                    i++;
                                }
                            }
                        }
                    }
                    arrayList.add(iC + 1, new io.ktor.util.pipeline.c(phase, new io.ktor.util.pipeline.g(reference)));
                }
                client.e.f(phase, new C4855b(handler2, hVar, 0));
                return;
            case 2:
                kotlin.jvm.functions.c handler3 = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler3, "handler");
                androidx.sqlite.db.a phase2 = new androidx.sqlite.db.a("BeforeReceive", 3);
                io.ktor.client.statement.e eVar = client.f;
                androidx.sqlite.db.a relativeTo = io.ktor.client.statement.e.f;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(relativeTo, "reference");
                Intrinsics.checkNotNullParameter(phase2, "phase");
                if (!eVar.e(phase2)) {
                    int iC2 = eVar.c(relativeTo);
                    if (iC2 == -1) {
                        throw new androidx.concurrent.futures.b("Phase " + relativeTo + " was not registered for this pipeline");
                    }
                    ArrayList arrayList2 = eVar.a;
                    Intrinsics.checkNotNullParameter(relativeTo, "relativeTo");
                    arrayList2.add(iC2, new io.ktor.util.pipeline.c(phase2, new io.ktor.util.pipeline.h()));
                }
                client.f.f(phase2, new c0(handler3, null, 0));
                return;
            case 3:
                kotlin.jvm.functions.c handler4 = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler4, "handler");
                client.e.f(io.ktor.client.request.f.i, new C4855b(handler4, null, 1));
                return;
            case 4:
                kotlin.jvm.functions.c handler5 = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler5, "handler");
                client.e.f(io.ktor.client.request.f.f, new c0(handler5, null, 1));
                return;
            default:
                kotlin.jvm.functions.c handler6 = (kotlin.jvm.functions.c) iVar;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(handler6, "handler");
                client.e.f(io.ktor.client.request.f.f, new c0(handler6, null, 2));
                return;
        }
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public io.ktor.util.a getKey() {
        return W.d;
    }
}
