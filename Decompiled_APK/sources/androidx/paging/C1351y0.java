package androidx.paging;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.paging.y0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1351y0 {
    public final InterfaceC4992i a;
    public final com.quizlet.data.repository.qclass.c b;
    public final com.google.firebase.platforminfo.c c;
    public final Function0 d;

    public C1351y0(InterfaceC4992i flow, com.quizlet.data.repository.qclass.c uiReceiver, com.google.firebase.platforminfo.c hintReceiver, Function0 cachedPageEvent) {
        Intrinsics.checkNotNullParameter(flow, "flow");
        Intrinsics.checkNotNullParameter(uiReceiver, "uiReceiver");
        Intrinsics.checkNotNullParameter(hintReceiver, "hintReceiver");
        Intrinsics.checkNotNullParameter(cachedPageEvent, "cachedPageEvent");
        this.a = flow;
        this.b = uiReceiver;
        this.c = hintReceiver;
        this.d = cachedPageEvent;
    }
}
