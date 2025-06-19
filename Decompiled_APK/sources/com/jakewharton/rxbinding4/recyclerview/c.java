package com.jakewharton.rxbinding4.recyclerview;

import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends i {
    public final /* synthetic */ int a;
    public final RecyclerView b;

    public c(RecyclerView view, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.f(view, "view");
                this.b = view;
                break;
            default:
                this.b = view;
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(l observer) {
        switch (this.a) {
            case 0:
                Intrinsics.f(observer, "observer");
                if (E.b(observer)) {
                    RecyclerView recyclerView = this.b;
                    b bVar = new b(recyclerView, observer);
                    observer.a(bVar);
                    recyclerView.j(bVar);
                    break;
                }
                break;
            default:
                Intrinsics.f(observer, "observer");
                if (E.b(observer)) {
                    RecyclerView recyclerView2 = this.b;
                    f fVar = new f(recyclerView2, observer);
                    observer.a(fVar);
                    recyclerView2.k(fVar.b);
                    break;
                }
                break;
        }
    }
}
