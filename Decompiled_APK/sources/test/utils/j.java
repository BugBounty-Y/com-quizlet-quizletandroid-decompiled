package test.utils;

import androidx.glance.appwidget.protobuf.Z;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ assistantMode.grading.d k;
    public final /* synthetic */ v l;
    public final /* synthetic */ J2 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(assistantMode.grading.d dVar, v vVar, J2 j2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = vVar;
        this.m = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        this.j = 1;
        Object objA = this.k.a(this.l, this.m, this);
        return objA == aVar ? aVar : objA;
    }
}
