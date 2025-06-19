package io.ktor.client.engine.okhttp;

import androidx.glance.appwidget.protobuf.Z;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Iterator it2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        f fVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                CoroutineContext.Element element = fVar.f.get(C5023i0.a);
                Intrinsics.d(element);
                this.j = 1;
                if (((InterfaceC5025j0) element).p(this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            while (it2.hasNext()) {
                A a = (A) ((Map.Entry) it2.next()).getValue();
                a.b.f();
                ((ThreadPoolExecutor) a.a.d()).shutdown();
            }
            return Unit.a;
        } finally {
            it2 = fVar.h.entrySet().iterator();
            while (it2.hasNext()) {
                A a2 = (A) ((Map.Entry) it2.next()).getValue();
                a2.b.f();
                ((ThreadPoolExecutor) a2.a.d()).shutdown();
            }
        }
    }
}
