package androidx.fragment.app;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class A extends C {
    public final /* synthetic */ androidx.arch.core.util.a a;
    public final /* synthetic */ AtomicReference b;
    public final /* synthetic */ androidx.activity.result.contract.a c;
    public final /* synthetic */ androidx.activity.result.a d;
    public final /* synthetic */ Fragment e;

    public A(Fragment fragment, androidx.arch.core.util.a aVar, AtomicReference atomicReference, androidx.activity.result.contract.a aVar2, androidx.activity.result.a aVar3) {
        this.e = fragment;
        this.a = aVar;
        this.b = atomicReference;
        this.c = aVar2;
        this.d = aVar3;
    }

    @Override // androidx.fragment.app.C
    public final void a() {
        Fragment fragment = this.e;
        this.b.set(((androidx.activity.result.h) this.a.mo0apply(null)).d(fragment.generateActivityResultKey(), fragment, this.c, this.d));
    }
}
