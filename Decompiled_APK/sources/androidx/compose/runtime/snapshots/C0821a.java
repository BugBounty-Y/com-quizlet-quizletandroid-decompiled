package androidx.compose.runtime.snapshots;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.snapshots.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0821a extends kotlin.jvm.internal.r implements Function1 {
    public static final C0821a b = new C0821a(1, 0);
    public static final C0821a c = new C0821a(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0821a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.Collection, java.util.List] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                synchronized (m.b) {
                    ?? r1 = m.h;
                    int size = r1.size();
                    for (int i = 0; i < size; i++) {
                        ((Function1) r1.get(i)).invoke(obj);
                    }
                }
                return Unit.a;
            default:
                return Unit.a;
        }
    }
}
