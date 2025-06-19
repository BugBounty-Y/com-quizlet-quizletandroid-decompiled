package androidx.glance.appwidget;

import android.content.BroadcastReceiver;
import android.util.Log;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i l;
    public final /* synthetic */ kotlinx.coroutines.internal.d m;
    public final /* synthetic */ BroadcastReceiver.PendingResult n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public B(Function2 function2, kotlinx.coroutines.internal.d dVar, BroadcastReceiver.PendingResult pendingResult, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = (kotlin.coroutines.jvm.internal.i) function2;
        this.m = dVar;
        this.n = pendingResult;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.l, this.m, this.n, hVar);
        b.k = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        kotlinx.coroutines.internal.d dVar = this.m;
        BroadcastReceiver.PendingResult pendingResult = this.n;
        try {
            try {
                if (i != 0) {
                    try {
                        if (i != 1) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                    } finally {
                        kotlinx.coroutines.E.i(dVar, null);
                    }
                } else {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
                    ?? r1 = this.l;
                    this.j = 1;
                    if (r1.invoke(c, this) == aVar) {
                        return aVar;
                    }
                }
            } finally {
                try {
                    pendingResult.finish();
                } catch (IllegalStateException e) {
                    Log.e("GlanceAppWidget", "Error thrown when trying to finish broadcast", e);
                }
            }
        } catch (CancellationException e2) {
            throw e2;
        } catch (Throwable th) {
            Log.e("GlanceAppWidget", "BroadcastReceiver execution failed", th);
        }
        return Unit.a;
    }
}
