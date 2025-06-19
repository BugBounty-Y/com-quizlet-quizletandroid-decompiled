package kotlinx.serialization.json.internal;

import androidx.appcompat.widget.C0070a;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.AbstractC4908b;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.h implements kotlin.jvm.functions.c {
    public int k;
    public /* synthetic */ AbstractC4908b l;
    public final /* synthetic */ C0070a m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(C0070a c0070a, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.m = c0070a;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        s sVar = new s(this.m, (kotlin.coroutines.h) obj3);
        sVar.l = (AbstractC4908b) obj;
        return sVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            AbstractC4908b abstractC4908b = this.l;
            C0070a c0070a = this.m;
            androidx.camera.camera2.internal.concurrent.a aVar2 = (androidx.camera.camera2.internal.concurrent.a) c0070a.c;
            byte bJ = aVar2.J();
            if (bJ == 1) {
                return c0070a.g(true);
            }
            if (bJ == 0) {
                return c0070a.g(false);
            }
            if (bJ != 6) {
                if (bJ == 8) {
                    return c0070a.f();
                }
                androidx.camera.camera2.internal.concurrent.a.r(aVar2, "Can't begin reading element, unexpected token", 0, null, 6);
                throw null;
            }
            this.k = 1;
            obj = C0070a.d(c0070a, abstractC4908b, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return (kotlinx.serialization.json.k) obj;
    }
}
