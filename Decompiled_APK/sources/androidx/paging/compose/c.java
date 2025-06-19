package androidx.paging.compose;

import androidx.appcompat.app.L;
import androidx.paging.A;
import androidx.paging.C1345v0;
import androidx.paging.C1351y0;
import androidx.paging.D0;
import androidx.paging.g1;
import androidx.paging.h1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import kotlin.collections.G;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class c {
    public final CoroutineContext a;
    public com.google.firebase.platforminfo.c b;
    public h1 c;
    public C1345v0 d;
    public final com.quizlet.data.repository.user.a e;
    public final CopyOnWriteArrayList f;
    public final L g;
    public volatile boolean h;
    public volatile int i;
    public final s0 j;
    public final Z k;
    public final d0 l;
    public final /* synthetic */ d m;

    public c(d dVar, CoroutineContext mainContext, C1351y0 c1351y0) {
        C1345v0 c1345v0;
        androidx.paging.L l;
        this.m = dVar;
        Intrinsics.checkNotNullParameter(mainContext, "mainContext");
        this.a = mainContext;
        this.c = new D0();
        C1345v0 c1345v02 = C1345v0.e;
        androidx.paging.L l2 = c1351y0 != null ? (androidx.paging.L) c1351y0.d.invoke() : null;
        if (l2 != null) {
            c1345v0 = new C1345v0(l2);
        } else {
            c1345v0 = C1345v0.e;
            Intrinsics.e(c1345v0, "null cannot be cast to non-null type androidx.paging.PageStore<T of androidx.paging.PageStore.Companion.initial>");
        }
        this.d = c1345v0;
        com.quizlet.data.repository.user.a aVar = new com.quizlet.data.repository.user.a(3);
        if (c1351y0 != null && (l = (androidx.paging.L) c1351y0.d.invoke()) != null) {
            aVar.x(l.e, l.f);
        }
        this.e = aVar;
        CopyOnWriteArrayList copyOnWriteArrayList = new CopyOnWriteArrayList();
        this.f = copyOnWriteArrayList;
        this.g = new L(true);
        this.j = e0.c(Boolean.FALSE);
        this.k = (Z) aVar.d;
        this.l = e0.a(0, 64, kotlinx.coroutines.channels.a.b);
        androidx.compose.ui.input.nestedscroll.b listener = new androidx.compose.ui.input.nestedscroll.b(this, 26);
        Intrinsics.checkNotNullParameter(listener, "listener");
        copyOnWriteArrayList.add(listener);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.paging.compose.c r5, java.util.List r6, int r7, int r8, boolean r9, androidx.paging.F r10, androidx.paging.F r11, com.google.firebase.platforminfo.c r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 358
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.compose.c.a(androidx.paging.compose.c, java.util.List, int, int, boolean, androidx.paging.F, androidx.paging.F, com.google.firebase.platforminfo.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final A b() {
        C1345v0 c1345v0 = this.d;
        int i = c1345v0.c;
        int i2 = c1345v0.d;
        ArrayList arrayList = c1345v0.a;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            G.u(arrayList2, ((g1) it2.next()).b);
        }
        return new A(arrayList2, i, i2);
    }
}
