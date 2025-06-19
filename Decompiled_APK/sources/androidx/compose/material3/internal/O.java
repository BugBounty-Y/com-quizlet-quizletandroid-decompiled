package androidx.compose.material3.internal;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.platform.C0971v;
import kotlin.jvm.internal.AbstractC4960t;

/* loaded from: classes.dex */
public final /* synthetic */ class O extends AbstractC4960t {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ O(int i, int i2, Class cls, Object obj, String str, String str2) {
        super(obj, cls, str, str2, i);
        this.a = i2;
    }

    @Override // kotlin.reflect.k
    public final Object get() {
        switch (this.a) {
            case 0:
                return ((InterfaceC0773a0) this.receiver).getValue();
            default:
                return ((C0971v) this.receiver).getLayoutDirection();
        }
    }
}
