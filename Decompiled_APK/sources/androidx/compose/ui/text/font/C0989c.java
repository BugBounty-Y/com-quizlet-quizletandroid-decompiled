package androidx.compose.ui.text.font;

import java.util.List;

/* renamed from: androidx.compose.ui.text.font.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0989c extends kotlin.coroutines.jvm.internal.c {
    public C0990d j;
    public List k;
    public A l;
    public int m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ C0990d p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0989c(C0990d c0990d, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = c0990d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.a(this);
    }
}
