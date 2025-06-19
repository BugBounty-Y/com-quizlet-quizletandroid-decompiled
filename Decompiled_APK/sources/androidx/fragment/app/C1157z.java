package androidx.fragment.app;

/* renamed from: androidx.fragment.app.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1157z implements androidx.arch.core.util.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1157z(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply */
    public final Object mo0apply(Object obj) {
        switch (this.a) {
            case 0:
                Fragment fragment = (Fragment) this.b;
                Object obj2 = fragment.mHost;
                return obj2 instanceof androidx.activity.result.i ? ((androidx.activity.result.i) obj2).getActivityResultRegistry() : fragment.requireActivity().getActivityResultRegistry();
            default:
                return (androidx.activity.result.h) this.b;
        }
    }
}
