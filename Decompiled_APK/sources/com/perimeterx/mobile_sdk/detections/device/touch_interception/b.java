package com.perimeterx.mobile_sdk.detections.device.touch_interception;

import com.perimeterx.mobile_sdk.session.l;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.TimerTask;
import kotlin.coroutines.n;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes2.dex */
public final class b extends TimerTask {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // java.util.TimerTask, java.lang.Runnable
    public final void run() throws Throwable {
        int i = 1;
        switch (this.a) {
            case 0:
                e eVar = e.a;
                e.c(f.d);
                break;
            default:
                l lVar = l.a;
                F f = new F();
                kotlin.coroutines.h hVar = null;
                E.D(n.a, new com.perimeterx.mobile_sdk.session.f(f, hVar, i));
                if (f.a) {
                    J j = new J();
                    E.D(n.a, new com.perimeterx.mobile_sdk.session.f(j, hVar, 0));
                    Iterator it2 = ((ArrayList) j.a).iterator();
                    Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                    while (it2.hasNext()) {
                        Object next = it2.next();
                        Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                        com.perimeterx.mobile_sdk.session.d dVar = (com.perimeterx.mobile_sdk.session.d) next;
                        dVar.getClass();
                        E.A(E.c(O.a), null, null, new com.perimeterx.mobile_sdk.session.n(dVar, hVar, i), 3);
                    }
                    break;
                }
                break;
        }
    }
}
