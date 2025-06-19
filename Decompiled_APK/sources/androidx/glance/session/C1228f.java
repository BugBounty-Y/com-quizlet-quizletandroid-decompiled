package androidx.glance.session;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.session.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1228f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ w m;
    public final /* synthetic */ s n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1228f(Context context, w wVar, s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = context;
        this.m = wVar;
        this.n = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1228f c1228f = new C1228f(this.l, this.m, this.n, hVar);
        c1228f.k = obj;
        return c1228f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1228f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        C1226d c1226d;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Context context = this.l;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            c1226d = (C1226d) this.k;
            try {
                Z.e(obj);
                context.unregisterReceiver(c1226d);
                return obj;
            } catch (Throwable th) {
                th = th;
                context.unregisterReceiver(c1226d);
                throw th;
            }
        }
        Z.e(obj);
        C1226d c1226d2 = new C1226d(new androidx.credentials.playservices.controllers.BeginSignIn.d(11, (kotlinx.coroutines.C) this.k, this.n));
        context.registerReceiver(c1226d2, C1226d.c);
        try {
            c1226d2.a(context);
            w wVar = this.m;
            this.k = c1226d2;
            this.j = 1;
            obj = wVar.invoke(this);
            if (obj == aVar) {
                return aVar;
            }
            c1226d = c1226d2;
            context.unregisterReceiver(c1226d);
            return obj;
        } catch (Throwable th2) {
            th = th2;
            c1226d = c1226d2;
            context.unregisterReceiver(c1226d);
            throw th;
        }
    }
}
