package androidx.recyclerview.widget;

/* renamed from: androidx.recyclerview.widget.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1360d extends AbstractC1389s {
    public final /* synthetic */ androidx.fragment.app.y0 a;

    public C1360d(androidx.fragment.app.y0 y0Var) {
        this.a = y0Var;
    }

    @Override // androidx.recyclerview.widget.AbstractC1389s
    public final boolean areContentsTheSame(int i, int i2) {
        androidx.fragment.app.y0 y0Var = this.a;
        Object obj = y0Var.c.get(i);
        Object obj2 = y0Var.d.get(i2);
        if (obj != null && obj2 != null) {
            return ((AbstractC1358c) ((C1364f) y0Var.f).b.b).a(obj, obj2);
        }
        if (obj == null && obj2 == null) {
            return true;
        }
        throw new AssertionError();
    }

    @Override // androidx.recyclerview.widget.AbstractC1389s
    public final boolean areItemsTheSame(int i, int i2) {
        androidx.fragment.app.y0 y0Var = this.a;
        Object obj = y0Var.c.get(i);
        Object obj2 = y0Var.d.get(i2);
        return (obj == null || obj2 == null) ? obj == null && obj2 == null : ((AbstractC1358c) ((C1364f) y0Var.f).b.b).b(obj, obj2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1389s
    public final Object getChangePayload(int i, int i2) {
        androidx.fragment.app.y0 y0Var = this.a;
        Object obj = y0Var.c.get(i);
        Object obj2 = y0Var.d.get(i2);
        if (obj == null || obj2 == null) {
            throw new AssertionError();
        }
        ((AbstractC1358c) ((C1364f) y0Var.f).b.b).getClass();
        return null;
    }

    @Override // androidx.recyclerview.widget.AbstractC1389s
    public final int getNewListSize() {
        return this.a.d.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1389s
    public final int getOldListSize() {
        return this.a.c.size();
    }
}
