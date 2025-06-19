package com.braze.managers;

import android.content.BroadcastReceiver;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.managers.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1502o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ r b;
    public final /* synthetic */ BroadcastReceiver.PendingResult c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1502o(r rVar, BroadcastReceiver.PendingResult pendingResult, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = rVar;
        this.c = pendingResult;
    }

    public static final String a() {
        return "Failed to log throwable during seal session.";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1502o c1502o = new C1502o(this.b, this.c, hVar);
        c1502o.a = obj;
        return c1502o;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1502o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        r rVar = this.b;
        ReentrantLock reentrantLock = rVar.h;
        reentrantLock.lock();
        try {
            try {
                rVar.i();
            } catch (Exception e) {
                try {
                    rVar.c.b(e, Throwable.class);
                } catch (Exception e2) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new K(26), 4, (Object) null);
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            this.c.finish();
            return unit;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }
}
