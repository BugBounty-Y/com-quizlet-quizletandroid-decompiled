package androidx.compose.foundation.text;

import androidx.compose.ui.layout.InterfaceC0894o;
import java.util.List;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0551z implements androidx.compose.ui.layout.K {
    public final /* synthetic */ C0492h0 a;
    public final /* synthetic */ kotlin.jvm.internal.r b;
    public final /* synthetic */ androidx.compose.ui.text.input.A c;
    public final /* synthetic */ androidx.compose.ui.text.input.s d;
    public final /* synthetic */ androidx.compose.ui.unit.b e;
    public final /* synthetic */ int f;

    /* JADX WARN: Multi-variable type inference failed */
    public C0551z(C0492h0 c0492h0, Function1 function1, androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.s sVar, androidx.compose.ui.unit.b bVar, int i) {
        this.a = c0492h0;
        this.b = (kotlin.jvm.internal.r) function1;
        this.c = a;
        this.d = sVar;
        this.e = bVar;
        this.f = i;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        C0492h0 c0492h0 = this.a;
        c0492h0.a.a(interfaceC0894o.getLayoutDirection());
        com.quizlet.remote.model.notes.e eVar = c0492h0.a.j;
        if (eVar != null) {
            return AbstractC0484d0.q(eVar.d());
        }
        throw new IllegalStateException("layoutIntrinsics must be called first");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x025a  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0112 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0134  */
    /* JADX WARN: Type inference failed for: r2v21, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M r24, java.util.List r25, long r26) {
        /*
            Method dump skipped, instructions count: 622
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.C0551z.mo1measure3p2s80s(androidx.compose.ui.layout.M, java.util.List, long):androidx.compose.ui.layout.L");
    }
}
