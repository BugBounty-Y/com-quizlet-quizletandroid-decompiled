package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import java.net.URL;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.c j;
    public J k;
    public URL l;
    public com.perimeterx.mobile_sdk.business_logic.b m;
    public int n;
    public final /* synthetic */ J o;
    public final /* synthetic */ URL p;
    public final /* synthetic */ com.perimeterx.mobile_sdk.business_logic.b q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(J j, URL url, com.perimeterx.mobile_sdk.business_logic.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = j;
        this.p = url;
        this.q = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.sync.c cVar;
        URL url;
        J j;
        com.perimeterx.mobile_sdk.business_logic.b bVar;
        Iterator it2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.n;
        if (i == 0) {
            Z.e(obj);
            cVar = l.e;
            this.j = cVar;
            J j2 = this.o;
            this.k = j2;
            url = this.p;
            this.l = url;
            com.perimeterx.mobile_sdk.business_logic.b bVar2 = this.q;
            this.m = bVar2;
            this.n = 1;
            if (cVar.d(this) == aVar) {
                return aVar;
            }
            j = j2;
            bVar = bVar2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            bVar = this.m;
            url = this.l;
            j = this.k;
            cVar = this.j;
            Z.e(obj);
        }
        try {
            try {
                it2 = l.c.iterator();
            } catch (Throwable th) {
                cVar.f(null);
                throw th;
            }
        } catch (NoSuchElementException unused) {
        }
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((d) next).h(url, bVar)) {
                j.a = next;
                Unit unit = Unit.a;
                cVar.f(null);
                return unit;
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }
}
