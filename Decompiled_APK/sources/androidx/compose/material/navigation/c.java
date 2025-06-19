package androidx.compose.material.navigation;

import androidx.compose.material.C0575s;
import androidx.compose.material.G;
import androidx.compose.material.b0;
import androidx.compose.material.e0;
import androidx.compose.material.f0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            e0 e0Var = this.k.c;
            this.j = 1;
            G gD = e0Var.a.d();
            f0 f0Var = f0.b;
            boolean zContainsKey = gD.a.containsKey(f0Var);
            C0575s c0575s = e0Var.a;
            if (b0.a[((f0) ((L0) c0575s.f).getValue()).ordinal()] == 1) {
                G gD2 = c0575s.d();
                f0 f0Var2 = f0.c;
                if (gD2.a.containsKey(f0Var2)) {
                    f0Var = f0Var2;
                }
            } else if (!zContainsKey) {
                f0Var = f0.a;
            }
            Object objA = e0.a(e0Var, f0Var, this);
            if (objA != obj2) {
                objA = Unit.a;
            }
            if (objA == obj2) {
                return obj2;
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
