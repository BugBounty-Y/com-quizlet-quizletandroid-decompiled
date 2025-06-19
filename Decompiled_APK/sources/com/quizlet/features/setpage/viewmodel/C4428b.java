package com.quizlet.features.setpage.viewmodel;

import com.quizlet.features.setpage.screenstates.C4425e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: com.quizlet.features.setpage.viewmodel.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4428b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ P b;

    public /* synthetic */ C4428b(P p, int i) {
        this.a = i;
        this.b = p;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.j1.j(C4425e.a);
                break;
            case 1:
                this.b.j1.j(C4425e.a);
                break;
            case 2:
                this.b.j1.j(C4425e.a);
                break;
            case 3:
                this.b.j1.j(C4425e.a);
                break;
            default:
                P p = this.b;
                p.X.j(Boolean.TRUE);
                p.f.A("set_page_ad_load_success");
                break;
        }
        return Unit.a;
    }
}
