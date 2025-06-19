package androidx.glance.session;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.glance.session.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1230h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C1231i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1230h(C1231i c1231i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c1231i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1230h(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1230h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.k.b();
            C1231i c1231i = this.k;
            this.j = 1;
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(this));
            c5028l.r();
            synchronized (c1231i.c) {
                c1231i.d = 20;
                c1231i.f = c5028l;
                Unit unit = Unit.a;
            }
            c5028l.u(new androidx.credentials.playservices.controllers.BeginSignIn.c(c1231i, 4));
            Object objQ = c5028l.q();
            if (objQ == aVar) {
                Intrinsics.checkNotNullParameter(this, "frame");
            }
            if (objQ == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
