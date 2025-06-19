package androidx.compose.foundation.text.input.internal;

import android.view.View;
import androidx.compose.ui.platform.V;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.input.internal.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0499e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ V l;
    public final /* synthetic */ androidx.activity.compose.d m;
    public final /* synthetic */ g n;
    public final /* synthetic */ w o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0499e(V v, androidx.activity.compose.d dVar, g gVar, w wVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = v;
        this.m = dVar;
        this.n = gVar;
        this.o = wVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0499e c0499e = new C0499e(this.l, this.m, this.n, this.o, hVar);
        c0499e.k = obj;
        return c0499e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((C0499e) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.n;
        try {
            if (i != 0) {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                throw new KotlinNothingValueException();
            }
            Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            z zVar = A.a;
            V v = this.l;
            View view = v.a;
            zVar.getClass();
            u uVar = new u(view);
            B b = new B(v.a, new C0498d(this.o), uVar);
            if (androidx.compose.foundation.text.handwriting.e.a) {
                kotlinx.coroutines.E.A(c, null, null, new C0497c(gVar, uVar, null), 3);
            }
            androidx.activity.compose.d dVar = this.m;
            if (dVar != null) {
                dVar.invoke(b);
            }
            gVar.c = b;
            this.j = 1;
            v.a(b, this);
            return aVar;
        } catch (Throwable th) {
            gVar.c = null;
            throw th;
        }
    }
}
