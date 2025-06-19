package androidx.camera.view;

import androidx.camera.camera2.internal.p0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements androidx.camera.core.impl.utils.futures.a, androidx.arch.core.util.a {
    public final /* synthetic */ p0 a;

    public /* synthetic */ b(p0 p0Var) {
        this.a = p0Var;
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public com.google.common.util.concurrent.e apply(Object obj) {
        return ((j) this.a.e).l();
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply */
    public Object mo0apply(Object obj) {
        this.a.n(i.b);
        return null;
    }
}
