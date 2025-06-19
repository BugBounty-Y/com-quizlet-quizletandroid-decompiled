package androidx.room;

import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c extends k {
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(String[] strArr, Object obj, int i) {
        super(strArr);
        this.b = i;
        this.c = obj;
    }

    @Override // androidx.room.k
    public final void a(Set tables) {
        switch (this.b) {
            case 0:
                ((kotlinx.coroutines.channels.h) this.c).o(Unit.a);
                break;
            default:
                Intrinsics.checkNotNullParameter(tables, "tables");
                androidx.arch.core.executor.b bVarP = androidx.arch.core.executor.b.p();
                v vVar = ((w) this.c).u;
                if (!bVarP.a.q()) {
                    bVarP.q(vVar);
                    break;
                } else {
                    vVar.run();
                    break;
                }
        }
    }
}
