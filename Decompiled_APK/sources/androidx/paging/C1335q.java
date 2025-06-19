package androidx.paging;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.paging.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1335q {
    public int a;
    public int b;
    public final C4927s c = new C4927s();
    public final io.ktor.client.plugins.api.d d = new io.ktor.client.plugins.api.d(3);
    public F e;
    public boolean f;

    public final void a(N event) {
        Intrinsics.checkNotNullParameter(event, "event");
        this.f = true;
        boolean z = event instanceof L;
        C4927s c4927s = this.c;
        io.ktor.client.plugins.api.d dVar = this.d;
        if (!z) {
            if (event instanceof J) {
                ((J) event).getClass();
                dVar.z(null, D.c);
                throw null;
            }
            if (event instanceof M) {
                M m = (M) event;
                dVar.y(m.a);
                this.e = m.b;
                return;
            }
            return;
        }
        L l = (L) event;
        dVar.y(l.e);
        this.e = l.f;
        int iOrdinal = l.a.ordinal();
        int i = l.c;
        int i2 = l.d;
        List list = l.b;
        if (iOrdinal == 0) {
            c4927s.clear();
            this.b = i2;
            this.a = i;
            c4927s.addAll(list);
            return;
        }
        if (iOrdinal != 1) {
            if (iOrdinal != 2) {
                return;
            }
            this.b = i2;
            c4927s.addAll(list);
            return;
        }
        this.a = i;
        int size = list.size() - 1;
        kotlin.ranges.h.d.getClass();
        kotlin.ranges.i it2 = new kotlin.ranges.h(size, 0, -1).iterator();
        while (it2.c) {
            c4927s.addFirst(list.get(it2.nextInt()));
        }
    }

    public final List b() {
        if (!this.f) {
            return kotlin.collections.K.a;
        }
        ArrayList arrayList = new ArrayList();
        F fB = this.d.B();
        C4927s c4927s = this.c;
        if (c4927s.isEmpty()) {
            arrayList.add(new M(fB, this.e));
            return arrayList;
        }
        L l = L.g;
        arrayList.add(AbstractC1348x.a(CollectionsKt.w0(c4927s), this.a, this.b, fB, this.e));
        return arrayList;
    }
}
