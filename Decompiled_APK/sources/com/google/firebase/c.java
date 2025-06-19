package com.google.firebase;

import androidx.camera.camera2.internal.c0;
import com.google.firebase.components.q;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class c implements com.google.firebase.components.d {
    public static final c b = new c(0);
    public static final c c = new c(1);
    public static final c d = new c(2);
    public static final c e = new c(3);
    public static final c f = new c(4);
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        switch (this.a) {
            case 1:
                Object objF = c0Var.f(new q(com.google.firebase.annotations.concurrent.a.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF);
            case 2:
                Object objF2 = c0Var.f(new q(com.google.firebase.annotations.concurrent.c.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF2, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF2);
            case 3:
                Object objF3 = c0Var.f(new q(com.google.firebase.annotations.concurrent.b.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF3, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF3);
            default:
                Object objF4 = c0Var.f(new q(com.google.firebase.annotations.concurrent.d.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF4, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF4);
        }
    }
}
