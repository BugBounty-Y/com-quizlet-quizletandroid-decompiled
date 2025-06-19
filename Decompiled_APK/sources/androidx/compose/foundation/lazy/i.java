package androidx.compose.foundation.lazy;

import androidx.compose.runtime.W0;

/* loaded from: classes.dex */
public final /* synthetic */ class i extends kotlin.jvm.internal.z {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(int i, int i2, Class cls, Object obj, String str, String str2) {
        super(obj, cls, str, str2, i);
        this.a = i2;
    }

    @Override // kotlin.reflect.k
    public final Object get() {
        switch (this.a) {
            case 0:
                return ((W0) this.receiver).getValue();
            case 1:
                return ((W0) this.receiver).getValue();
            case 2:
                return ((W0) this.receiver).getValue();
            case 3:
                return ((W0) this.receiver).getValue();
            case 4:
                return ((W0) this.receiver).getValue();
            default:
                return this.receiver.getClass().getSimpleName();
        }
    }
}
