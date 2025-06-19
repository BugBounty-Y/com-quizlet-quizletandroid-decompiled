package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4702k implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ OldHomeFragment b;

    public /* synthetic */ C4702k(OldHomeFragment oldHomeFragment, int i) {
        this.a = i;
        this.b = oldHomeFragment;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        OldHomeFragment oldHomeFragment = this.b;
        switch (this.a) {
            case 0:
                Integer it2 = (Integer) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                String str = OldHomeFragment.d1;
                RecyclerView recyclerViewX = oldHomeFragment.X();
                Y y = oldHomeFragment.t;
                if (y != null) {
                    X5.b(recyclerViewX, y, false, null, -1);
                    return;
                } else {
                    Intrinsics.m("viewModel");
                    throw null;
                }
            default:
                io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                oldHomeFragment.I(p0);
                return;
        }
    }
}
