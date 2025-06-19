package com.quizlet.features.setpage.studypreview.ui;

import com.quizlet.features.setpage.studypreview.j;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class h implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.setpage.studypreview.g b;

    public /* synthetic */ h(com.quizlet.features.setpage.studypreview.g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                this.b.C(new j(((Number) obj).intValue()));
                break;
            default:
                this.b.C(new com.quizlet.features.setpage.studypreview.h(((Boolean) obj).booleanValue()));
                break;
        }
        return Unit.a;
    }
}
