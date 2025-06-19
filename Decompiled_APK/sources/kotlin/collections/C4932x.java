package kotlin.collections;

import java.util.Iterator;
import kotlin.jvm.functions.Function0;

/* renamed from: kotlin.collections.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4932x extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ Object[] a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4932x(Object[] objArr) {
        super(0);
        this.a = objArr;
    }

    @Override // kotlin.jvm.functions.Function0
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final Iterator<Object> invoke() {
        return kotlin.jvm.internal.O.f(this.a);
    }
}
