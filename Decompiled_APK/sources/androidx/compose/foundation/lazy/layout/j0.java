package androidx.compose.foundation.lazy.layout;

import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class j0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.saveable.i b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j0(androidx.compose.runtime.saveable.i iVar, int i) {
        super(1);
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.runtime.saveable.i iVar = this.b;
                return Boolean.valueOf(iVar != null ? iVar.a(obj) : true);
            default:
                return new l0(this.b, (Map) obj);
        }
    }
}
