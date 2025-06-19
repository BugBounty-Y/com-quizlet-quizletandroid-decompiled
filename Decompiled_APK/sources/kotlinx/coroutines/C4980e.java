package kotlinx.coroutines;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4980e {
    public static final /* synthetic */ AtomicIntegerFieldUpdater b = AtomicIntegerFieldUpdater.newUpdater(C4980e.class, "notCompletedCount$volatile");
    public final H[] a;
    private volatile /* synthetic */ int notCompletedCount$volatile;

    public C4980e(H[] hArr) {
        this.a = hArr;
        this.notCompletedCount$volatile = hArr.length;
    }

    public final Object a(kotlin.coroutines.jvm.internal.i frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        InterfaceC5025j0[] interfaceC5025j0Arr = this.a;
        int length = interfaceC5025j0Arr.length;
        C4976c[] c4976cArr = new C4976c[length];
        for (int i = 0; i < length; i++) {
            InterfaceC5025j0 interfaceC5025j0 = interfaceC5025j0Arr[i];
            ((q0) interfaceC5025j0).start();
            C4976c c4976c = new C4976c(this, c5028l);
            c4976c.f = E.v(interfaceC5025j0, true, c4976c);
            Unit unit = Unit.a;
            c4976cArr[i] = c4976c;
        }
        C4978d c4978d = new C4978d(c4976cArr);
        for (int i2 = 0; i2 < length; i2++) {
            C4976c c4976c2 = c4976cArr[i2];
            c4976c2.getClass();
            C4976c.h.set(c4976c2, c4978d);
        }
        if (c5028l.y()) {
            c4978d.a();
        } else {
            c5028l.v(c4978d);
        }
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }
}
