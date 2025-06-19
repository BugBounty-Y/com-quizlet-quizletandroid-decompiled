package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.view.View;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.studiablemodels.StudiableImage;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import java.util.Objects;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class B implements View.OnClickListener {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ com.quizlet.studiablemodels.i b;
    public final /* synthetic */ C4756b c;

    public /* synthetic */ B(C4756b c4756b, com.quizlet.studiablemodels.i iVar) {
        this.c = c4756b;
        this.b = iVar;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                long j = this.b.a;
                C4756b c4756b = this.c;
                QStarIconView qStarIconView = c4756b.i;
                qStarIconView.setSelected(!qStarIconView.isSelected());
                boolean zIsSelected = qStarIconView.isSelected();
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d dVar = c4756b.a;
                com.quizlet.remote.model.notes.e eVar = dVar.c;
                com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                if (!zIsSelected) {
                    K k = K.a;
                    io.reactivex.rxjava3.subjects.d dVar2 = (io.reactivex.rxjava3.subjects.d) eVar.f;
                    dVar2.getClass();
                    Objects.requireNonNull(k, "defaultItem is null");
                    io.reactivex.rxjava3.internal.observers.e eVarI = new C4885d(dVar2, k, 1).i(new com.quizlet.learn.checkpoint.data.b(eVar, j, 1), gVar);
                    Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(eVarI, "<this>");
                    dVar.A(eVarI);
                    break;
                } else {
                    K k2 = K.a;
                    io.reactivex.rxjava3.subjects.d dVar3 = (io.reactivex.rxjava3.subjects.d) eVar.f;
                    dVar3.getClass();
                    Objects.requireNonNull(k2, "defaultItem is null");
                    io.reactivex.rxjava3.internal.observers.e eVarI2 = new C4885d(dVar3, k2, 1).i(new com.quizlet.learn.checkpoint.data.b(eVar, j, 0), gVar);
                    Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(eVarI2, "<this>");
                    dVar.A(eVarI2);
                    break;
                }
            default:
                assistantMode.enums.m side = assistantMode.enums.m.c;
                com.quizlet.studiablemodels.i iVar = this.b;
                iVar.getClass();
                Intrinsics.checkNotNullParameter(side, "side");
                StudiableImage image = iVar.c.d;
                if (image != null) {
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d dVar4 = this.c.a;
                    dVar4.getClass();
                    Intrinsics.checkNotNullParameter(image, "image");
                    String strA = image.a();
                    if (strA != null) {
                        dVar4.g.j(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m(strA));
                        break;
                    }
                }
                break;
        }
    }

    public /* synthetic */ B(com.quizlet.studiablemodels.i iVar, C4756b c4756b) {
        this.b = iVar;
        this.c = c4756b;
    }
}
