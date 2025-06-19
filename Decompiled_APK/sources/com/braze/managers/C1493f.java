package com.braze.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.braze.managers.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1493f extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public C1493f(kotlin.coroutines.h hVar) {
        super(1, hVar);
    }

    public static final String b(AbstractC1491d abstractC1491d) {
        throw null;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C1493f(hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return new C1493f((kotlin.coroutines.h) obj).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        ReentrantLock reentrantLock = C1495h.n;
        reentrantLock.lock();
        try {
            C1495h.m = null;
            Iterator it2 = C1495h.o.iterator();
            while (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                try {
                    throw null;
                } catch (Exception e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) C1495h.k, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(7), 4, (Object) null);
                    it2.remove();
                }
            }
            ArrayList arrayList = C1495h.o;
            if (arrayList == null || !arrayList.isEmpty()) {
                Iterator it3 = arrayList.iterator();
                if (it3.hasNext()) {
                    if (it3.next() == null) {
                        throw null;
                    }
                    throw new ClassCastException();
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            return unit;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }
}
