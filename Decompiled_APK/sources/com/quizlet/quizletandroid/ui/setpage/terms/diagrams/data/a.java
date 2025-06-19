package com.quizlet.quizletandroid.ui.setpage.terms.diagrams.data;

import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements io.reactivex.rxjava3.functions.b {
    public final /* synthetic */ long a;

    public a(long j) {
        this.a = j;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public final Object apply(Object obj, Object obj2) {
        DBImageRef imageRef = (DBImageRef) obj;
        List diagramShapes = (List) obj2;
        Intrinsics.checkNotNullParameter(imageRef, "imageRef");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        DiagramData.Builder builder = new DiagramData.Builder();
        builder.d(this.a);
        DBImage image = imageRef.getImage();
        Intrinsics.checkNotNullExpressionValue(image, "getImage(...)");
        builder.c(image);
        builder.b(diagramShapes);
        return builder.a();
    }
}
