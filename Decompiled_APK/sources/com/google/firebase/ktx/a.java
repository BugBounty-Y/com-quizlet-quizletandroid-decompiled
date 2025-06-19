package com.google.firebase.ktx;

import androidx.camera.camera2.internal.c0;
import com.google.firebase.annotations.concurrent.b;
import com.google.firebase.annotations.concurrent.c;
import com.google.firebase.components.d;
import com.google.firebase.components.q;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class a implements d {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public static final a e = new a(3);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.components.d
    public final Object f(c0 c0Var) {
        switch (this.a) {
            case 0:
                Object objF = c0Var.f(new q(com.google.firebase.annotations.concurrent.a.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF);
            case 1:
                Object objF2 = c0Var.f(new q(c.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF2, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF2);
            case 2:
                Object objF3 = c0Var.f(new q(b.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF3, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF3);
            default:
                Object objF4 = c0Var.f(new q(com.google.firebase.annotations.concurrent.d.class, Executor.class));
                Intrinsics.checkNotNullExpressionValue(objF4, "c.get(Qualified.qualifie…a, Executor::class.java))");
                return E.p((Executor) objF4);
        }
    }
}
