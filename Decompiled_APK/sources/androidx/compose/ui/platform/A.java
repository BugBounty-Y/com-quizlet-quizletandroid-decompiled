package androidx.compose.ui.platform;

import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.core.view.C1038b;

/* loaded from: classes.dex */
public final class A extends com.airbnb.lottie.network.c {
    public final /* synthetic */ int c;
    public final /* synthetic */ C1038b d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ A(C1038b c1038b, int i) {
        super(11);
        this.c = i;
        this.d = c1038b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:13:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:308:0x0600  */
    /* JADX WARN: Removed duplicated region for block: B:314:0x060a  */
    /* JADX WARN: Removed duplicated region for block: B:406:0x0794  */
    /* JADX WARN: Removed duplicated region for block: B:426:0x07d5  */
    /* JADX WARN: Removed duplicated region for block: B:429:0x07da  */
    /* JADX WARN: Removed duplicated region for block: B:512:0x098d  */
    /* JADX WARN: Removed duplicated region for block: B:547:0x0a18  */
    /* JADX WARN: Type inference failed for: r6v117, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v118, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v119, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v120, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v127, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r6v128, types: [java.util.ArrayList] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final androidx.core.view.accessibility.e C(int r37) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 3214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.A.C(int):androidx.core.view.accessibility.e");
    }

    @Override // com.airbnb.lottie.network.c
    public void h(int i, androidx.core.view.accessibility.e eVar, String str, Bundle bundle) {
        switch (this.c) {
            case 0:
                ((F) this.d).j(i, eVar, str, bundle);
                break;
        }
    }

    @Override // com.airbnb.lottie.network.c
    public final androidx.core.view.accessibility.e k(int i) {
        switch (this.c) {
            case 0:
                return C(i);
            default:
                return new androidx.core.view.accessibility.e(AccessibilityNodeInfo.obtain(((androidx.customview.widget.a) this.d).n(i).a));
        }
    }

    @Override // com.airbnb.lottie.network.c
    public final androidx.core.view.accessibility.e q(int i) {
        switch (this.c) {
            case 0:
                return k(((F) this.d).n);
            default:
                androidx.customview.widget.a aVar = (androidx.customview.widget.a) this.d;
                int i2 = i == 2 ? aVar.k : aVar.l;
                if (i2 == Integer.MIN_VALUE) {
                    return null;
                }
                return k(i2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:586:0x0213, code lost:
    
        r2 = null;
     */
    /* JADX WARN: Removed duplicated region for block: B:169:0x026f  */
    /* JADX WARN: Removed duplicated region for block: B:513:0x070f  */
    /* JADX WARN: Type inference failed for: r1v174, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // com.airbnb.lottie.network.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean y(int r26, int r27, android.os.Bundle r28) {
        /*
            Method dump skipped, instructions count: 2236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.A.y(int, int, android.os.Bundle):boolean");
    }
}
