package com.quizlet.data.repository.classmembership;

import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.j256.ormlite.dao.Dao;
import com.quizlet.assembly.compose.listitems.r;
import io.reactivex.rxjava3.functions.j;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import kotlin.u;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;
    public final /* synthetic */ long c;

    public /* synthetic */ a(c cVar, long j, int i) {
        this.a = i;
        this.b = cVar;
        this.c = j;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.activitycenter.b bVar = (com.quizlet.data.repository.activitycenter.b) this.b.b;
                Object value = ((u) ((com.google.mlkit.vision.documentscanner.internal.c) bVar.c).b).getValue();
                Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
                return AbstractC3771z.b((com.quizlet.shared.usecase.folderstudymaterials.a) bVar.b, com.quizlet.local.ormlite.util.b.b((Dao) value, x.c("\n                SELECT * FROM group_membership\n                WHERE userId = " + this.c + "\n                AND " + A.a(true) + "\n        ")));
            default:
                c cVar = this.b;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) cVar.d, new C1510p(cVar, this.c, 12), new r(17));
        }
    }
}
