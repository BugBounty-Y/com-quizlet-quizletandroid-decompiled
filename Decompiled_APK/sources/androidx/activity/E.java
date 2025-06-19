package androidx.activity;

import java.util.ListIterator;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ L b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ E(L l, int i) {
        super(1);
        this.a = i;
        this.b = l;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Object objPrevious;
        Object objPrevious2;
        switch (this.a) {
            case 0:
                C0030b backEvent = (C0030b) obj;
                Intrinsics.checkNotNullParameter(backEvent, "backEvent");
                L l = this.b;
                C4927s c4927s = l.b;
                ListIterator listIterator = c4927s.listIterator(c4927s.a());
                while (true) {
                    if (listIterator.hasPrevious()) {
                        objPrevious = listIterator.previous();
                        if (((D) objPrevious).a) {
                        }
                    } else {
                        objPrevious = null;
                    }
                }
                D d = (D) objPrevious;
                if (l.c != null) {
                    l.b();
                }
                l.c = d;
                if (d != null) {
                    d.d(backEvent);
                }
                break;
            default:
                C0030b backEvent2 = (C0030b) obj;
                Intrinsics.checkNotNullParameter(backEvent2, "backEvent");
                L l2 = this.b;
                D d2 = l2.c;
                if (d2 == null) {
                    C4927s c4927s2 = l2.b;
                    ListIterator listIterator2 = c4927s2.listIterator(c4927s2.a());
                    while (true) {
                        if (listIterator2.hasPrevious()) {
                            objPrevious2 = listIterator2.previous();
                            if (((D) objPrevious2).a) {
                            }
                        } else {
                            objPrevious2 = null;
                        }
                    }
                    d2 = (D) objPrevious2;
                }
                if (d2 != null) {
                    d2.c(backEvent2);
                }
                break;
        }
        return Unit.a;
    }
}
