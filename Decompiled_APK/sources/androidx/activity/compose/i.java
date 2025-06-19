package androidx.activity.compose;

import androidx.activity.D;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class i extends D {
    public final /* synthetic */ InterfaceC0773a0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(InterfaceC0773a0 interfaceC0773a0, boolean z) {
        super(z);
        this.d = interfaceC0773a0;
    }

    @Override // androidx.activity.D
    public final void b() {
        ((Function0) this.d.getValue()).invoke();
    }
}
