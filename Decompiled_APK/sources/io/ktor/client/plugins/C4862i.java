package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: io.ktor.client.plugins.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4862i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ io.ktor.client.statement.b m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4862i(Object obj, io.ktor.client.statement.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = obj;
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4862i c4862i = new C4862i(this.l, this.m, hVar);
        c4862i.k = obj;
        return c4862i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4862i) create((io.ktor.utils.io.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        io.ktor.client.statement.b bVar = this.m;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                io.ktor.utils.io.B b = (io.ktor.utils.io.B) this.k;
                io.ktor.utils.io.n nVar = (io.ktor.utils.io.n) this.l;
                io.ktor.utils.io.t tVar = b.a;
                this.j = 1;
                obj = AbstractC3234p7.h(nVar, tVar, Long.MAX_VALUE, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            ((Number) obj).longValue();
            return Unit.a;
        } catch (CancellationException e) {
            kotlinx.coroutines.E.i(bVar, e);
            throw e;
        } catch (Throwable th) {
            kotlinx.coroutines.E.i(bVar, kotlinx.coroutines.E.a("Receive failed", th));
            throw th;
        }
    }
}
