package androidx.activity;

import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class M extends D {
    public final /* synthetic */ int d = 1;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(UpgradeActivity upgradeActivity) {
        super(true);
        this.e = upgradeActivity;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.activity.D
    public final void b() {
        Object obj = this.e;
        switch (this.d) {
            case 0:
                ((kotlin.jvm.internal.r) obj).invoke(this);
                break;
            case 1:
                ((androidx.navigation.r) obj).f();
                break;
            default:
                com.quizlet.upgrade.data.o oVar = new com.quizlet.upgrade.data.o(null);
                String str = UpgradeActivity.v;
                ((UpgradeActivity) obj).b0(oVar);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(androidx.navigation.r rVar) {
        super(false);
        this.e = rVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public M(Function1 function1) {
        super(true);
        this.e = (kotlin.jvm.internal.r) function1;
    }
}
