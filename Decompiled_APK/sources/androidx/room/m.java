package androidx.room;

import java.lang.ref.WeakReference;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m extends k {
    public final n b;
    public final WeakReference c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(n tracker, c delegate) {
        super(delegate.a);
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = tracker;
        this.c = new WeakReference(delegate);
    }

    @Override // androidx.room.k
    public final void a(Set tables) {
        Intrinsics.checkNotNullParameter(tables, "tables");
        k kVar = (k) this.c.get();
        if (kVar == null) {
            this.b.c(this);
        } else {
            kVar.a(tables);
        }
    }
}
