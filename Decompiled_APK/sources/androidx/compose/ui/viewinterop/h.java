package androidx.compose.ui.viewinterop;

import android.os.Parcelable;
import android.util.SparseArray;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class h extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ p b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(p pVar, int i) {
        super(0);
        this.a = i;
        this.b = pVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.getLayoutNode().z();
                break;
            case 1:
                p pVar = this.b;
                if (pVar.e && pVar.isAttachedToWindow() && pVar.getView().getParent() == pVar) {
                    pVar.getSnapshotObserver().a(pVar, a.c, pVar.getUpdate());
                }
                break;
            case 2:
                SparseArray<Parcelable> sparseArray = new SparseArray<>();
                this.b.w.saveHierarchyState(sparseArray);
                break;
            case 3:
                p pVar2 = this.b;
                pVar2.getReleaseBlock().invoke(pVar2.w);
                p.l(pVar2);
                break;
            case 4:
                p pVar3 = this.b;
                pVar3.getResetBlock().invoke(pVar3.w);
                break;
            default:
                p pVar4 = this.b;
                pVar4.getUpdateBlock().invoke(pVar4.w);
                break;
        }
        return Unit.a;
    }
}
