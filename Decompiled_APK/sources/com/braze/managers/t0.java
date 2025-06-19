package com.braze.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.storage.C1514a;
import com.braze.support.BrazeLogger;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ u0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t0(u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = u0Var;
    }

    public static final String a() {
        return "User cache was locked, waiting.";
    }

    public static final String b() {
        return "User cache notified. Continuing UserDependencyManager shutdown";
    }

    public static final String c() {
        return "Device cache was locked, waiting.";
    }

    public static final String d() {
        return "Device cache notified. Continuing UserDependencyManager shutdown";
    }

    public static final String e() {
        return "Exception while shutting down dispatch manager. Continuing.";
    }

    public static final String f() {
        return "Exception while stopping data sync. Continuing.";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t0 t0Var = new t0(this.b, hVar);
        t0Var.a = obj;
        return t0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        t0 t0Var = new t0(this.b, (kotlin.coroutines.h) obj2);
        t0Var.a = (kotlinx.coroutines.C) obj;
        return t0Var.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater;
        com.braze.storage.r rVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        try {
            kotlinx.coroutines.sync.h hVar = (kotlinx.coroutines.sync.h) this.b.a().a;
            hVar.getClass();
            atomicIntegerFieldUpdater = kotlinx.coroutines.sync.h.g;
            if (Math.max(atomicIntegerFieldUpdater.get(hVar), 0) == 0) {
                BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
                BrazeLogger.brazelog$default(brazeLogger, (Object) c, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new P(14), 6, (Object) null);
                com.braze.storage.h0 h0VarA = this.b.a();
                h0VarA.getClass();
                kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1514a(h0VarA, null));
                BrazeLogger.brazelog$default(brazeLogger, (Object) c, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(15), 7, (Object) null);
            }
            rVar = this.b.k;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new P(18), 4, (Object) null);
        }
        if (rVar == null) {
            Intrinsics.m("deviceCache");
            throw null;
        }
        kotlinx.coroutines.sync.h hVar2 = (kotlinx.coroutines.sync.h) rVar.a;
        hVar2.getClass();
        if (Math.max(atomicIntegerFieldUpdater.get(hVar2), 0) == 0) {
            BrazeLogger brazeLogger2 = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger2, (Object) c, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new P(16), 6, (Object) null);
            com.braze.storage.r rVar2 = this.b.k;
            if (rVar2 == null) {
                Intrinsics.m("deviceCache");
                throw null;
            }
            kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1514a(rVar2, null));
            BrazeLogger.brazelog$default(brazeLogger2, (Object) c, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(17), 7, (Object) null);
        }
        this.b.E.e();
        this.b.l.c();
        this.b.q.l();
        try {
            this.b.p.f();
        } catch (Exception e2) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.W, (Throwable) e2, false, (Function0) new P(19), 4, (Object) null);
        }
        return Unit.a;
    }
}
